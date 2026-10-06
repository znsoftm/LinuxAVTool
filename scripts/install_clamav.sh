#!/usr/bin/env bash
#
# sysinfo - automatic ClamAV (libclamav) installer.
#
# Installs the ClamAV engine library and a virus signature database so that the
# sysinfo security module can inspect files in-process through the libclamav C
# API. The default mode never needs root: the distribution packages are
# downloaded and unpacked into a private prefix, then the signature database is
# fetched from the ClamAV update service. With --system (and root privileges)
# the distribution package manager is used instead.
#
# Usage:
#   scripts/install_clamav.sh [options]
#
#     --prefix DIR       install prefix (default: <repo>/third_party/clamav)
#     --system           install system wide with the package manager (root)
#     --no-database      install the library only, skip the signature database
#     --force            reinstall even when a working installation is detected
#     --mirror URL       signature database base URL
#     -h, --help         show this help
#
# Environment:
#   SYSINFO_CLAMAV_PREFIX   alternative install prefix
#   CLAMAV_DB_MIRROR        alternative signature database base URL
#
# Exit status: 0 when the library is usable, non-zero otherwise. A failure to
# fetch the signature database is reported as a warning: the library is still
# installed and can be pointed at an existing database later.

set -u

PROGRAM_NAME="$(basename -- "$0")"

info() { printf '%s: %s\n' "$PROGRAM_NAME" "$*"; }
warn() { printf '%s: warning: %s\n' "$PROGRAM_NAME" "$*" >&2; }
die() { printf '%s: error: %s\n' "$PROGRAM_NAME" "$*" >&2; exit 1; }

usage() {
    sed -n '3,27p' -- "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || die "cannot resolve the script directory"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)" || die "cannot resolve the repository root"

PREFIX="${SYSINFO_CLAMAV_PREFIX:-$REPO_ROOT/third_party/clamav}"
SYSTEM_INSTALL=0
WITH_DATABASE=1
FORCE=0
MIRROR="${CLAMAV_DB_MIRROR:-https://database.clamav.net}"

# The update service rejects requests that do not look like a ClamAV client.
UPDATE_USER_AGENT="ClamWin/0.103.0 (OS: Windows; ARCH: x86; CPU: i386; NS: 1.0.1; GT: 0.103.0)"

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)
            [ $# -ge 2 ] || die "--prefix requires a directory"
            PREFIX="$2"
            shift 2
            ;;
        --prefix=*)
            PREFIX="${1#--prefix=}"
            shift
            ;;
        --system)
            SYSTEM_INSTALL=1
            shift
            ;;
        --no-database)
            WITH_DATABASE=0
            shift
            ;;
        --force)
            FORCE=1
            shift
            ;;
        --mirror)
            [ $# -ge 2 ] || die "--mirror requires a URL"
            MIRROR="$2"
            shift 2
            ;;
        --mirror=*)
            MIRROR="${1#--mirror=}"
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown option: $1 (try --help)"
            ;;
    esac
done

DATABASE_DIR="$PREFIX/database"

library_ready() {
    [ -f "$PREFIX/include/clamav.h" ] || return 1
    [ -e "$PREFIX/lib/libclamav.so" ] || return 1
    # clamav.h pulls in the OpenSSL headers, including the generated
    # architecture specific opensslconf.h.
    [ -f "$PREFIX/include/openssl/ssl.h" ] || return 1
    [ -f "$PREFIX/include/openssl/opensslconf.h" ] || return 1
    return 0
}

database_ready() {
    [ -d "$DATABASE_DIR" ] || return 1
    for candidate in "$DATABASE_DIR"/*.cvd "$DATABASE_DIR"/*.cld; do
        [ -e "$candidate" ] && return 0
    done
    return 1
}

if [ "$FORCE" -eq 0 ] && library_ready; then
    if [ "$WITH_DATABASE" -eq 0 ] || database_ready; then
        mkdir -p "$PREFIX/certs" 2>/dev/null || true
        info "ClamAV is already installed in $PREFIX"
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# System wide installation (package manager, needs root).
# ---------------------------------------------------------------------------
if [ "$SYSTEM_INSTALL" -eq 1 ]; then
    SUDO=""
    if [ "$(id -u)" -ne 0 ]; then
        command -v sudo >/dev/null 2>&1 || die "--system requires root or sudo"
        SUDO="sudo"
    fi
    command -v apt-get >/dev/null 2>&1 || die "--system requires apt-get"
    $SUDO apt-get update || warn "apt-get update failed, continuing"
    $SUDO apt-get install -y libclamav-dev clamav-freshclam || die "package installation failed"
    if [ "$WITH_DATABASE" -eq 1 ]; then
        $SUDO systemctl stop clamav-freshclam >/dev/null 2>&1 || true
        command -v freshclam >/dev/null 2>&1 && { $SUDO freshclam || warn "freshclam failed"; }
    fi
    info "system wide ClamAV installation complete"
    exit 0
fi

# ---------------------------------------------------------------------------
# Private installation (no root required).
# ---------------------------------------------------------------------------
command -v dpkg-deb >/dev/null 2>&1 || die "dpkg-deb is required for a rootless installation"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/sysinfo-clamav.XXXXXX")" || die "cannot create a temporary directory"
cleanup() {
    case "$WORK" in
        "${TMPDIR:-/tmp}"/sysinfo-clamav.*) rm -rf -- "$WORK" ;;
    esac
}
trap cleanup EXIT INT TERM

info "installing libclamav into $PREFIX"

# ---- 1. obtain the distribution packages ----------------------------------
# clamav.h includes <openssl/ssl.h> unconditionally, so the OpenSSL development
# headers are needed to compile against it even though libclamav links them
# dynamically. They are unpacked into the private prefix like the rest.
CLAMAV_PACKAGES="libclamav-dev libclamav12 libssl-dev"

packages_available() {
    for candidate in "$WORK"/*.deb; do
        [ -e "$candidate" ] && return 0
    done
    return 1
}

if command -v apt-get >/dev/null 2>&1; then
    ( cd "$WORK" && apt-get download $CLAMAV_PACKAGES ) || \
        warn "apt-get download failed"
fi

if ! packages_available; then
    info "resolving package URLs directly"
    command -v curl >/dev/null 2>&1 || die "curl is required to fetch the packages"
    urls="$(apt-get download --print-uris $CLAMAV_PACKAGES 2>/dev/null | \
            awk -F"'" 'NF > 1 { print $2 }')"
    [ -n "$urls" ] || die "cannot resolve the libclamav package URLs"
    for url in $urls; do
        name="$(basename -- "$url")"
        info "downloading $name"
        curl -fL --retry 3 --retry-delay 2 -o "$WORK/$name" "$url" || die "cannot download $url"
    done
fi

packages_available || die "no libclamav package could be downloaded"

# ---- 2. unpack into the prefix --------------------------------------------
mkdir -p "$PREFIX" || die "cannot create $PREFIX"
for package in "$WORK"/*.deb; do
    info "unpacking $(basename -- "$package")"
    dpkg-deb -x "$package" "$PREFIX" || die "cannot unpack $package"
done

# Convenience layout: <prefix>/include and <prefix>/lib next to the merged
# usr/ tree the packages contain.
if [ -d "$PREFIX/usr/include" ] && [ ! -e "$PREFIX/include" ]; then
    ln -s usr/include "$PREFIX/include"
fi

MULTIARCH=""
for candidate in "$PREFIX"/usr/lib/*-linux-gnu*; do
    if [ -d "$candidate" ]; then
        MULTIARCH="$(basename -- "$candidate")"
        break
    fi
done
[ -n "$MULTIARCH" ] || die "cannot locate the library directory in the unpacked packages"

if [ ! -e "$PREFIX/lib" ]; then
    ln -s "usr/lib/$MULTIARCH" "$PREFIX/lib"
fi

[ -e "$PREFIX/lib/libclamav.so" ] || die "libclamav.so is missing after unpacking"

# Debian/Ubuntu keep some generated headers (openssl/opensslconf.h) in an
# architecture specific include directory. Merge those into the plain include
# tree with symlinks so a single -I flag is enough.
for multiarch_include in "$PREFIX"/usr/include/*-linux-gnu; do
    [ -d "$multiarch_include" ] || continue
    ( cd "$multiarch_include" && find . -type f -print ) | while IFS= read -r relative; do
        relative="${relative#./}"
        target="$PREFIX/usr/include/$relative"
        if [ ! -e "$target" ]; then
            mkdir -p -- "$(dirname -- "$target")"
            ln -s -- "$multiarch_include/$relative" "$target"
        fi
    done
done

# ---- 3. rewrite the pkg-config file with the real prefix -------------------
PC_SOURCE="$PREFIX/usr/lib/$MULTIARCH/pkgconfig/libclamav.pc"
PC_TARGET="$PREFIX/lib/pkgconfig/libclamav.pc"
PC_VERSION="unknown"
PC_EXTRA=""
if [ -f "$PC_SOURCE" ]; then
    PC_VERSION="$(grep -m1 '^Version:' "$PC_SOURCE" | cut -d: -f2- | tr -d ' ')"
    PC_EXTRA="$(grep -E '^(Requires|Libs\.private|Requires\.private):' "$PC_SOURCE" || true)"
fi
[ -n "$PC_VERSION" ] || PC_VERSION="unknown"
mkdir -p "$PREFIX/lib/pkgconfig"
{
    printf 'prefix=%s\n' "$PREFIX"
    printf 'exec_prefix=${prefix}\n'
    printf 'libdir=${prefix}/lib\n'
    printf 'includedir=${prefix}/include\n\n'
    printf 'Name: libclamav\n'
    printf 'Description: ClamAV antivirus engine library\n'
    printf 'Version: %s\n' "$PC_VERSION"
    printf 'Libs: -L${libdir} -lclamav\n'
    printf 'Cflags: -I${includedir}\n'
    if [ -n "$PC_EXTRA" ]; then
        printf '%s\n' "$PC_EXTRA"
    fi
} > "$PC_TARGET"

info "libclamav $PC_VERSION installed ($PREFIX/lib/libclamav.so)"

# ---- 4. signature database -------------------------------------------------
looks_like_database() {
    head -c 16 -- "$1" 2>/dev/null | grep -qa 'ClamAV-VDB'
}

download_database_file() {
    name="$1"
    target="$DATABASE_DIR/$name"
    if [ -s "$target" ] && looks_like_database "$target"; then
        info "signature database $name is already present"
        return 0
    fi
    for base in "$MIRROR" "https://db.local.clamav.net"; do
        info "downloading $name from $base"
        rm -f -- "$target.part"
        if command -v curl >/dev/null 2>&1; then
            curl -fL --retry 3 --retry-delay 2 -A "$UPDATE_USER_AGENT" \
                 -o "$target.part" "$base/$name" || continue
        elif command -v wget >/dev/null 2>&1; then
            wget -q --user-agent="$UPDATE_USER_AGENT" -O "$target.part" "$base/$name" || continue
        else
            warn "neither curl nor wget is available"
            return 1
        fi
        if looks_like_database "$target.part"; then
            mv -f -- "$target.part" "$target"
            info "$name installed"
            return 0
        fi
        warn "$base/$name did not return a ClamAV signature database"
        rm -f -- "$target.part"
    done
    return 1
}

DATABASE_OK=1
if [ "$WITH_DATABASE" -eq 1 ]; then
    mkdir -p "$DATABASE_DIR" || die "cannot create $DATABASE_DIR"
    # libclamav refuses to load its database when the code-signing certificate
    # directory does not exist, so an empty one is kept next to the signatures.
    mkdir -p "$PREFIX/certs"
    for name in main.cvd daily.cvd; do
        download_database_file "$name" || DATABASE_OK=0
    done
fi

info "library : $PREFIX/lib/libclamav.so"
info "headers : $PREFIX/include"
if [ "$WITH_DATABASE" -eq 1 ] && [ "$DATABASE_OK" -eq 1 ]; then
    info "database: $DATABASE_DIR"
else
    warn "no complete signature database in $DATABASE_DIR"
    warn "run '$PROGRAM_NAME --prefix $PREFIX' again when the update service is reachable"
fi

exit 0
