[English](README_EN.md) | [简体中文](README.md)

# sysinfo

A Linux system information tool (C++11). It collects locale/language, memory,
and disk information, and uses the **libclamav C API** to detect the ClamAV
engine status and run on-demand virus scans.

The ClamAV engine library is **installed automatically** during the first
configuration (no root required): distribution packages are downloaded and
unpacked into `third_party/clamav`, and the official virus database is fetched,
so a single `cmake -S . -B build` yields a fully functional build.

## Build

```sh
cmake -S . -B build -G Ninja     # auto-installs libclamav when missing
cmake --build build
```

If libclamav is not present on the machine at first configuration,
`scripts/install_clamav.sh` runs: it unpacks
`libclamav-dev` / `libclamav12` / `libssl-dev` into `third_party/clamav`, then
downloads `main.cvd` + `daily.cvd` from `database.clamav.net` (about 110 MB,
network required). If it is already installed, this step is skipped and nothing
is downloaded again.

Related CMake options:

| Option | Default | Purpose |
| --- | --- | --- |
| `SYSINFO_USE_CLAMAV` | `ON` | When off, does not link libclamav and only detects the command-line ClamAV |
| `SYSINFO_AUTO_INSTALL_CLAMAV` | `ON` | When off, the configure step will not install over the network |
| `ClamAV_ROOT` | `third_party/clamav` | ClamAV installation prefix |

You can also run the install script on its own:

```sh
scripts/install_clamav.sh                  # install into third_party/clamav
scripts/install_clamav.sh --prefix=/opt/clamav
scripts/install_clamav.sh --no-database    # libraries only, no virus database
scripts/install_clamav.sh --system         # install into the system via apt (root required)
scripts/install_clamav.sh --force          # force reinstall
```

Environment variables available at runtime:

| Variable | Purpose |
| --- | --- |
| `SYSINFO_CLAMAV_DB` | Virus database directory (takes precedence over the compiled-in default) |
| `CLAMAV_DATADIR` | Same as above, for compatibility with ClamAV conventions |
| `SYSINFO_CLAMAV_CERTS` | Certificate directory for CVD signature verification |

## Usage

```sh
./build/sysinfo              # enters the interactive UI automatically in a terminal
./build/sysinfo --plain      # force a plain-text report
./build/sysinfo --lang=en    # force an English report (default: auto-detect via LANG/LC_*)
./build/sysinfo --scan=/path # scan the given path with ClamAV
./build/sysinfo --scan=/path --remove                # delete infected files
./build/sysinfo --scan=/path --quarantine=/tmp/q     # quarantine infected files
```

## Security scanning

The `Security` tab shows the engine status and scan results. Scanning happens
in-process through the libclamav C API:

* `cl_init` / `cl_engine_new` / `cl_load(CL_DB_STDOPT)` / `cl_engine_compile`
  build the engine on first use; all subsequent scans reuse the same compiled
  engine (the virus database is loaded only once).
* Each file is scanned with `cl_scanfile_ex` and judged by `cl_verdict_t`;
  the directory tree is walked recursively by the program itself. An explicitly
  given scan target that is a symbolic link is followed once (for example
  `/lib` → `usr/lib`, `/bin` → `usr/bin`), while symlinks inside the directory
  tree are never followed, so link cycles cannot make the walk diverge.
* If, at the end of the walk, neither a file nor a directory was visited (the
  target is unreadable, a special file, or a broken link), the scan is reported
  as a failure instead of "no virus found", so that scanning nothing is never
  mistaken for being clean.
* The engine and database versions come from `cl_retver()` and
  `cl_engine_get_num(CL_ENGINE_DB_VERSION / CL_ENGINE_DB_TIME)`, and the total
  signature count comes from the output of `cl_load`.

If libclamav was disabled at build time, or no usable database is available
locally, the tool falls back to running a `clamscan` / `clamdscan` subprocess
and parsing its output, so it works in both cases.

> Note: libclamav refuses to load a virus database when the certificate
> directory does not exist (Debian/Ubuntu default `/etc/clamav/certs`). The
> install script creates an empty certificate directory under the prefix, and
> the program automatically picks an existing directory to pass to
> `CL_ENGINE_CVDCERTSDIR`.

### Interactive interface (TUI)

Enabled by default when running in a terminal; it can also be requested
explicitly with `--tui`. It uses ANSI escape sequences and termios, with no
dependency on ncurses.

| Key | Action |
| --- | --- |
| `Tab` / `Shift-Tab` / `←` `→` | Switch between the Memory / Disk / Security / Language tabs |
| `↑` `↓` / `j` `k` | Scroll the current tab up and down |
| `s` | Start a ClamAV scan (scans the current directory when no target is given) |
| `r` | Re-collect system information |
| `q` / `Ctrl-C` | Quit |

Collecting system information and running scans both happen on background
threads; the interface shows a spinner and progress-bar animation meanwhile, so
rendering is never blocked. If `--scan=<path>` is given, the scan starts
automatically after entering the interface.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Report only, or scan result is clean |
| 1 | Scan found threats |
| 2 | Scan could not run / argument error |

## Directory structure

```
include/sysinfo/  Public headers
src/              Implementation
  main.cpp        Entry point and command-line parsing, plain-text report
  tui.cpp         Interactive terminal interface
  report.cpp      Report content construction (shared by both views)
  text_table.cpp  Fixed-width table rendering (aligned to terminal width, CJK-aware)
  locale_info.cpp Locale / language detection
  memory_info.cpp /proc/meminfo memory information
  disk_info.cpp   statvfs + /proc/mounts disk information
  clamav_scan.cpp libclamav C API integration and scanning (falls back to a clamscan subprocess when the library is missing)
  i18n.cpp        Chinese/English strings and terminal column-width calculation
cmake/
  FindClamAV.cmake  Locates libclamav (including triggering auto-install)
scripts/
  install_clamav.sh Root-free installation of libclamav + virus database
third_party/clamav/ Auto-install output (libraries, headers, virus database; ignored by .gitignore)
```
