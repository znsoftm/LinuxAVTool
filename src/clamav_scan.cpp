// sysinfo - ClamAV anti-virus integration implementation
//
// When the binary is built with libclamav (SYSINFO_HAVE_LIBCLAMAV, the default)
// files are scanned in-process through the ClamAV C API. Otherwise, or when the
// library has no usable signature database, the scanner is spawned as a child
// process and its textual report is parsed, so the tool keeps working with only
// a ClamAV command line installation.

#include "sysinfo/clamav_scan.h"

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

#ifdef SYSINFO_HAVE_LIBCLAMAV
#include <clamav.h>
#endif

namespace sysinfo {

namespace {

// A signature database older than this is reported as outdated. ClamAV ships
// updates several times a day, so a week of silence means something is wrong.
const std::int64_t kSignatureMaxAgeDays = 7;

// Guard against a scanner that never terminates.
const std::uint32_t kDefaultTimeoutSeconds = 900;

std::string trim(const std::string& text) {
    std::size_t begin = 0;
    std::size_t end = text.size();
    while (begin < end && (text[begin] == ' ' || text[begin] == '\t' ||
                           text[begin] == '\r' || text[begin] == '\n')) {
        ++begin;
    }
    while (end > begin && (text[end - 1] == ' ' || text[end - 1] == '\t' ||
                           text[end - 1] == '\r' || text[end - 1] == '\n')) {
        --end;
    }
    return text.substr(begin, end - begin);
}

bool isExecutable(const std::string& path) {
    return !path.empty() && access(path.c_str(), X_OK) == 0;
}

// Search PATH (then a few conventional directories) for an executable.
std::string findOnPath(const std::string& name) {
    std::vector<std::string> dirs;
    const char* pathEnv = std::getenv("PATH");
    if (pathEnv != NULL) {
        std::string path(pathEnv);
        std::size_t start = 0;
        while (start <= path.size()) {
            const std::size_t sep = path.find(':', start);
            const std::string dir =
                path.substr(start, sep == std::string::npos ? std::string::npos
                                                            : sep - start);
            if (!dir.empty()) {
                dirs.push_back(dir);
            }
            if (sep == std::string::npos) {
                break;
            }
            start = sep + 1;
        }
    }
    dirs.push_back("/usr/local/bin");
    dirs.push_back("/usr/bin");
    dirs.push_back("/bin");
    dirs.push_back("/usr/local/sbin");
    dirs.push_back("/usr/sbin");

    for (std::size_t i = 0; i < dirs.size(); ++i) {
        const std::string candidate = dirs[i] + "/" + name;
        if (isExecutable(candidate)) {
            return candidate;
        }
    }
    return std::string();
}

// Run `argv` and collect the combined stdout/stderr output. Returns false when
// the process could not be started. `exitCode` is -1 on spawn failure and on
// timeout (in which case the child is killed).
bool runProcess(const std::vector<std::string>& argv, std::uint32_t timeoutSeconds,
                std::string& output, int& exitCode) {
    output.clear();
    exitCode = -1;
    if (argv.empty()) {
        return false;
    }

    int pipeFds[2];
    if (pipe(pipeFds) != 0) {
        return false;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(pipeFds[0]);
        close(pipeFds[1]);
        return false;
    }

    if (pid == 0) {
        // Child: wire the write end to stdout and stderr.
        close(pipeFds[0]);
        dup2(pipeFds[1], STDOUT_FILENO);
        dup2(pipeFds[1], STDERR_FILENO);
        if (pipeFds[1] > STDERR_FILENO) {
            close(pipeFds[1]);
        }

        std::vector<char*> raw;
        raw.reserve(argv.size() + 1);
        for (std::size_t i = 0; i < argv.size(); ++i) {
            raw.push_back(const_cast<char*>(argv[i].c_str()));
        }
        raw.push_back(NULL);
        execv(raw[0], &raw[0]);
        _exit(127);  // exec failed
    }

    // Parent: drain the pipe so the child never blocks on a full buffer.
    close(pipeFds[1]);
    char buffer[4096];
    bool timedOut = false;
    const std::time_t deadline =
        std::time(NULL) + static_cast<std::time_t>(timeoutSeconds);

    for (;;) {
        struct pollfd pfd;
        pfd.fd = pipeFds[0];
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int ready = poll(&pfd, 1, 200);
        if (ready > 0 && (pfd.revents & (POLLIN | POLLHUP))) {
            const ssize_t n = read(pipeFds[0], buffer, sizeof(buffer));
            if (n > 0) {
                output.append(buffer, static_cast<std::size_t>(n));
                continue;
            }
            if (n == 0) {
                break;  // EOF
            }
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (ready < 0 && errno != EINTR) {
            break;
        }
        if (std::time(NULL) >= deadline) {
            timedOut = true;
            kill(pid, SIGKILL);
            break;
        }
    }
    close(pipeFds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }

    if (timedOut) {
        exitCode = -1;
        return false;
    }
    if (WIFEXITED(status)) {
        exitCode = WEXITSTATUS(status);
        return true;
    }
    exitCode = -1;
    return false;
}

// Split `text` into trimmed lines.
std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        lines.push_back(trim(line));
    }
    return lines;
}

// Parse "ClamAV <engine>/<sigversion>/<date>" into its parts.
void parseVersionLine(const std::string& line, ScanEngine& engine) {
    const std::string prefix = "ClamAV ";
    if (line.compare(0, prefix.size(), prefix) != 0) {
        return;
    }
    std::string rest = line.substr(prefix.size());

    const std::size_t firstSlash = rest.find('/');
    if (firstSlash == std::string::npos) {
        engine.engineVersion = trim(rest);
        return;
    }
    engine.engineVersion = trim(rest.substr(0, firstSlash));

    const std::string tail = rest.substr(firstSlash + 1);
    const std::size_t secondSlash = tail.find('/');
    if (secondSlash == std::string::npos) {
        engine.signatureVersion = trim(tail);
        return;
    }
    engine.signatureVersion = trim(tail.substr(0, secondSlash));
    engine.signatureDate = trim(tail.substr(secondSlash + 1));
}

int monthNumber(const std::string& name) {
    static const char* kMonths[] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    for (int i = 0; i < 12; ++i) {
        if (name == kMonths[i]) {
            return i + 1;
        }
    }
    return 0;
}

// The signature date looks like "Sun Jan 12 08:39:42 2025"; the leading
// weekday is optional in some builds.
bool parseSignatureDate(const std::string& text, std::time_t& out) {
    std::istringstream stream(text);
    std::vector<std::string> tokens;
    std::string token;
    while (stream >> token) {
        tokens.push_back(token);
    }
    if (tokens.size() < 4) {
        return false;
    }
    // Drop a leading weekday such as "Sun".
    std::size_t index = 0;
    if (!tokens[0].empty() &&
        (tokens[0][0] < '0' || tokens[0][0] > '9') &&
        monthNumber(tokens[0]) == 0) {
        index = 1;
    }
    if (tokens.size() < index + 4) {
        return false;
    }

    const int month = monthNumber(tokens[index]);
    const int day = std::atoi(tokens[index + 1].c_str());
    const int year = std::atoi(tokens[index + 3].c_str());
    if (month == 0 || day <= 0 || year < 1970) {
        return false;
    }

    int hour = 0;
    int minute = 0;
    int second = 0;
    if (tokens[index + 2].size() >= 8) {
        const std::string& clock = tokens[index + 2];
        hour = std::atoi(clock.substr(0, 2).c_str());
        minute = std::atoi(clock.substr(3, 2).c_str());
        second = std::atoi(clock.substr(6, 2).c_str());
    }

    struct tm tmValue;
    std::memset(&tmValue, 0, sizeof(tmValue));
    tmValue.tm_year = year - 1900;
    tmValue.tm_mon = month - 1;
    tmValue.tm_mday = day;
    tmValue.tm_hour = hour;
    tmValue.tm_min = minute;
    tmValue.tm_sec = second;
    const std::time_t parsed = timegm(&tmValue);
    if (parsed <= 0) {
        return false;
    }
    out = parsed;
    return true;
}

// Parse a "Label: 1234" summary value out of the report lines.
bool summaryValue(const std::vector<std::string>& lines, const std::string& label,
                  std::uint64_t& out) {
    const std::string prefix = label + ":";
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (lines[i].compare(0, prefix.size(), prefix) == 0) {
            const std::string value = trim(lines[i].substr(prefix.size()));
            char* end = NULL;
            const long long parsed = std::strtoll(value.c_str(), &end, 10);
            if (end != value.c_str() && parsed >= 0) {
                out = static_cast<std::uint64_t>(parsed);
                return true;
            }
        }
    }
    return false;
}

bool summaryDouble(const std::vector<std::string>& lines, const std::string& label,
                   double& out) {
    const std::string prefix = label + ":";
    for (std::size_t i = 0; i < lines.size(); ++i) {
        if (lines[i].compare(0, prefix.size(), prefix) == 0) {
            const std::string value = trim(lines[i].substr(prefix.size()));
            std::istringstream stream(value);
            double parsed = 0.0;
            if (stream >> parsed) {
                out = parsed;
                return true;
            }
        }
    }
    return false;
}

#ifdef SYSINFO_HAVE_LIBCLAMAV

// ---------------------------------------------------------------------------
// libclamav session
// ---------------------------------------------------------------------------
//
// The compiled signature database is tens of megabytes and takes a moment to
// load, so one engine is created on first use and reused by every later scan
// of the process. Access is serialised: a cl_engine must not be used from
// several threads at once, and the interactive interface scans on a worker
// thread.

std::mutex& libraryMutex() {
    static std::mutex mutex;
    return mutex;
}

struct LibraryState {
    struct cl_engine* engine = NULL;
    std::string directory;
    std::uint64_t maxFileSize = 0;
    std::uint64_t signatures = 0;
    std::string error;
    bool attempted = false;

    // The engine is released when the process exits.
    ~LibraryState() {
        if (engine != NULL) {
            cl_engine_free(engine);
            engine = NULL;
        }
    }
};

LibraryState& libraryState() {
    static LibraryState state;
    return state;
}

void releaseLibraryEngine() {
    LibraryState& state = libraryState();
    if (state.engine != NULL) {
        cl_engine_free(state.engine);
        state.engine = NULL;
    }
}

std::string libraryPath() {
#ifdef SYSINFO_LIBCLAMAV_PATH
    return SYSINFO_LIBCLAMAV_PATH;
#else
    return "libclamav.so";
#endif
}

// Signature database directories, most specific first.
std::vector<std::string> databaseDirCandidates() {
    std::vector<std::string> dirs;
    const char* envDb = std::getenv("SYSINFO_CLAMAV_DB");
    if (envDb != NULL && envDb[0] != '\0') {
        dirs.push_back(envDb);
    }
    const char* clamEnv = std::getenv("CLAMAV_DATADIR");
    if (clamEnv != NULL && clamEnv[0] != '\0') {
        dirs.push_back(clamEnv);
    }
#ifdef SYSINFO_CLAMAV_DB_DIR
    dirs.push_back(SYSINFO_CLAMAV_DB_DIR);
#endif
    dirs.push_back("/var/lib/clamav");
    dirs.push_back("/usr/local/share/clamav");
    return dirs;
}

bool isDirectory(const std::string& path) {
    struct stat info;
    if (stat(path.c_str(), &info) != 0) {
        return false;
    }
    return S_ISDIR(info.st_mode);
}

// Directory holding the code-signing certificates. libclamav refuses to load
// its database at all when this points somewhere that does not exist (the
// Debian/Ubuntu default is /etc/clamav/certs), so a private installation keeps
// an empty one next to the signatures.
std::string certificatesDirectory(const std::string& databaseDir) {
    std::vector<std::string> candidates;
    const char* envCerts = std::getenv("SYSINFO_CLAMAV_CERTS");
    if (envCerts != NULL && envCerts[0] != '\0') {
        candidates.push_back(envCerts);
    }
    candidates.push_back("/etc/clamav/certs");
    const std::size_t slash = databaseDir.rfind('/');
    if (slash != std::string::npos && slash > 0) {
        candidates.push_back(databaseDir.substr(0, slash) + "/certs");
    }
    candidates.push_back(databaseDir + "/certs");

    for (std::size_t i = 0; i < candidates.size(); ++i) {
        if (isDirectory(candidates[i])) {
            return candidates[i];
        }
    }
    return databaseDir;  // last resort: any existing directory will do
}

// "Sun Jan 12 08:39:42 2025", the same shape clamscan --version prints.
std::string formatSignatureDate(std::time_t when) {
    struct tm tmValue;
    if (gmtime_r(&when, &tmValue) == NULL) {
        return std::string();
    }
    char buffer[64];
    if (strftime(buffer, sizeof(buffer), "%a %b %e %H:%M:%S %Y", &tmValue) == 0) {
        return std::string();
    }
    return std::string(buffer);
}

// Load the engine for `directory`, reusing a previously loaded one when the
// settings did not change. Returns NULL on failure with the reason stored in
// the shared state; a failed attempt is not retried on every scan.
struct cl_engine* acquireLibraryEngine(const std::string& directory,
                                       std::uint64_t maxFileSize) {
    LibraryState& state = libraryState();
    const bool sameConfiguration =
        state.directory == directory && state.maxFileSize == maxFileSize;
    if (sameConfiguration && state.engine != NULL) {
        return state.engine;
    }
    if (sameConfiguration && state.attempted) {
        return NULL;
    }

    releaseLibraryEngine();
    state.directory = directory;
    state.maxFileSize = maxFileSize;
    state.signatures = 0;
    state.attempted = true;
    state.error.clear();

    if (cl_init(CL_INIT_DEFAULT) != CL_SUCCESS) {
        state.error = "libclamav could not be initialised";
        return NULL;
    }

    struct cl_engine* engine = cl_engine_new();
    if (engine == NULL) {
        state.error = "cannot allocate a ClamAV engine";
        return NULL;
    }
    cl_engine_set_str(engine, CL_ENGINE_CVDCERTSDIR,
                      certificatesDirectory(directory).c_str());
    if (maxFileSize > 0) {
        cl_engine_set_num(engine, CL_ENGINE_MAX_FILESIZE,
                          static_cast<long long>(maxFileSize));
    }

    unsigned int signatures = 0;
    cl_error_t status =
        cl_load(directory.c_str(), engine, &signatures, CL_DB_STDOPT);
    if (status != CL_SUCCESS) {
        state.error = "cannot load the ClamAV signature database from " +
                      directory + ": " + cl_strerror(status);
        cl_engine_free(engine);
        return NULL;
    }
    status = cl_engine_compile(engine);
    if (status != CL_SUCCESS) {
        state.error = std::string("cannot compile the ClamAV engine: ") +
                      cl_strerror(status);
        cl_engine_free(engine);
        return NULL;
    }

    state.engine = engine;
    state.signatures = signatures;
    return engine;
}

// Describe the library engine, loading its database. Returns false when no
// usable database was found; `failure` then carries the reason.
bool detectLibraryEngine(ScanEngine& engine, std::string& failure) {
    engine.usingLibrary = true;
    engine.libraryPath = libraryPath();
    const char* version = cl_retver();
    if (version != NULL) {
        engine.engineVersion = version;
    }
    std::ostringstream level;
    level << cl_retflevel();
    engine.functionalLevel = level.str();

    const std::vector<std::string> dirs = databaseDirCandidates();
    for (std::size_t i = 0; i < dirs.size(); ++i) {
        if (access(dirs[i].c_str(), R_OK) != 0) {
            continue;
        }

        // The engine (and the shared state behind it) is also used by the scan
        // path, so it is only touched while holding the lock.
        std::lock_guard<std::mutex> lock(libraryMutex());
        struct cl_engine* clEngine = acquireLibraryEngine(dirs[i], 0);
        if (clEngine == NULL) {
            failure = libraryState().error;
            continue;
        }

        engine.available = true;
        engine.kind = ScanEngineKind::LibClamAV;
        engine.name = "libclamav";
        engine.databaseDir = dirs[i];
        engine.signatureCount = libraryState().signatures;

        int err = CL_SUCCESS;
        const long long dbVersion =
            cl_engine_get_num(clEngine, CL_ENGINE_DB_VERSION, &err);
        if (err == CL_SUCCESS && dbVersion > 0) {
            engine.signatureVersion = std::to_string(dbVersion);
        }

        err = CL_SUCCESS;
        const long long dbTime =
            cl_engine_get_num(clEngine, CL_ENGINE_DB_TIME, &err);
        if (err == CL_SUCCESS && dbTime > 0) {
            engine.signatureDate =
                formatSignatureDate(static_cast<std::time_t>(dbTime));
            const std::int64_t ageSeconds =
                static_cast<std::int64_t>(std::time(NULL)) -
                static_cast<std::int64_t>(dbTime);
            engine.signatureAgeDays = ageSeconds / 86400;
            engine.signatureOutdated =
                engine.signatureAgeDays > kSignatureMaxAgeDays;
        }
        return true;
    }

    if (failure.empty()) {
        failure = "no ClamAV signature database found (looked in " +
                  dirs[0] + " and other locations)";
    }
    return false;
}

// Move an infected file into the quarantine directory, avoiding collisions.
bool quarantineFile(const std::string& directory, const std::string& path,
                    std::string& movedTo) {
    if (mkdir(directory.c_str(), 0700) != 0 && errno != EEXIST) {
        return false;
    }

    std::string name = path;
    const std::size_t slash = name.rfind('/');
    if (slash != std::string::npos) {
        name = name.substr(slash + 1);
    }
    if (name.empty()) {
        name = "infected";
    }

    std::string candidate = directory + "/" + name;
    for (int suffix = 1; access(candidate.c_str(), F_OK) == 0; ++suffix) {
        std::ostringstream text;
        text << directory << '/' << name << '.' << suffix;
        candidate = text.str();
    }
    if (rename(path.c_str(), candidate.c_str()) != 0) {
        return false;
    }
    movedTo = candidate;
    return true;
}

// Scan one regular file and record a finding when a signature matches.
void scanFileWithLibrary(struct cl_engine* engine, const std::string& path,
                         const ScanOptions& options, ScanResult& result) {
    struct cl_scan_options scanOptions;
    std::memset(&scanOptions, 0, sizeof(scanOptions));
    scanOptions.general = CL_SCAN_GENERAL_ALLMATCHES;
    scanOptions.parse = CL_SCAN_PARSE_ARCHIVE | CL_SCAN_PARSE_ELF |
                        CL_SCAN_PARSE_PDF | CL_SCAN_PARSE_SWF |
                        CL_SCAN_PARSE_XMLDOCS | CL_SCAN_PARSE_MAIL |
                        CL_SCAN_PARSE_OLE2 | CL_SCAN_PARSE_HTML |
                        CL_SCAN_PARSE_PE | CL_SCAN_PARSE_ONENOTE;
    scanOptions.heuristic = CL_SCAN_HEURISTIC_BROKEN |
                            CL_SCAN_HEURISTIC_ENCRYPTED_ARCHIVE |
                            CL_SCAN_HEURISTIC_MACROS |
                            CL_SCAN_HEURISTIC_BROKEN_MEDIA;

    cl_verdict_t verdict = CL_VERDICT_NOTHING_FOUND;
    const char* alert = NULL;
    std::uint64_t scanned = 0;
    const cl_error_t status = cl_scanfile_ex(
        path.c_str(), &verdict, &alert, &scanned, engine, &scanOptions, NULL,
        NULL, NULL, NULL, NULL, NULL);

    result.scannedFiles += 1;
    result.dataScannedMiB += static_cast<double>(scanned) / (1024.0 * 1024.0);

    const bool detected = verdict == CL_VERDICT_STRONG_INDICATOR ||
                          verdict == CL_VERDICT_POTENTIALLY_UNWANTED ||
                          status == CL_VIRUS;
    if (!detected) {
        return;
    }

    ScanFinding finding;
    finding.path = path;
    finding.signature = (alert != NULL && alert[0] != '\0') ? alert : "unknown";
    result.findings.push_back(finding);
    result.infectedFiles += 1;

    // --remove / --quarantine act on the file that was just flagged.
    if (options.removeInfected) {
        unlink(path.c_str());
    } else if (!options.quarantineDir.empty()) {
        std::string movedTo;
        quarantineFile(options.quarantineDir, path, movedTo);
    }
}

// Walk `path` and scan every regular file. Symbolic links are not followed, so
// a link loop cannot make the walk diverge. Sets result.error on a timeout.
void walkAndScanWithLibrary(struct cl_engine* engine, const std::string& path,
                            const ScanOptions& options, ScanResult& result,
                            const std::chrono::steady_clock::time_point& deadline) {
    if (!result.error.empty()) {
        return;  // a previous entry aborted the scan
    }
    if (std::chrono::steady_clock::now() >= deadline) {
        result.error = "the scan exceeded its time limit";
        return;
    }

    struct stat info;
    if (lstat(path.c_str(), &info) != 0) {
        return;
    }
    if (S_ISLNK(info.st_mode)) {
        return;
    }
    if (S_ISDIR(info.st_mode)) {
        result.scannedDirectories += 1;
        if (!options.recursive) {
            return;
        }
        DIR* dir = opendir(path.c_str());
        if (dir == NULL) {
            return;
        }
        std::vector<std::string> children;
        struct dirent* entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..") {
                continue;
            }
            children.push_back(name);
        }
        closedir(dir);
        for (std::size_t i = 0; i < children.size(); ++i) {
            walkAndScanWithLibrary(engine, path + "/" + children[i], options,
                                   result, deadline);
            if (!result.error.empty()) {
                return;
            }
        }
        return;
    }
    if (S_ISREG(info.st_mode)) {
        scanFileWithLibrary(engine, path, options, result);
    }
}

ScanResult scanPathWithLibrary(const ScanEngine& engine,
                               const std::string& target,
                               const ScanOptions& options) {
    ScanResult result;
    result.target = target;

    std::lock_guard<std::mutex> lock(libraryMutex());
    struct cl_engine* clEngine =
        acquireLibraryEngine(engine.databaseDir, options.maxFileSizeBytes);
    if (clEngine == NULL) {
        result.error = libraryState().error.empty()
                           ? std::string("the ClamAV engine is unavailable")
                           : libraryState().error;
        return result;
    }

    struct stat info;
    if (stat(target.c_str(), &info) != 0) {
        result.error = "cannot access " + target + ": " + std::strerror(errno);
        return result;
    }

    const std::uint32_t timeout = options.timeoutSeconds > 0
                                      ? options.timeoutSeconds
                                      : kDefaultTimeoutSeconds;
    const std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
    walkAndScanWithLibrary(clEngine, target, options, result, deadline);

    if (!result.error.empty()) {
        return result;  // valid stays false: the scan did not finish
    }

    if (result.infectedFiles == 0 && !result.findings.empty()) {
        result.infectedFiles = result.findings.size();
    }
    result.infected = result.infectedFiles > 0 || !result.findings.empty();
    result.exitCode = result.infected ? 1 : 0;
    result.valid = true;
    return result;
}

#endif  // SYSINFO_HAVE_LIBCLAMAV

}  // namespace

ScanEngine detectScanEngine() {
    ScanEngine engine;

#ifdef SYSINFO_HAVE_LIBCLAMAV
    // Preferred: the engine library, driven in-process through its C API.
    std::string libraryFailure;
    if (detectLibraryEngine(engine, libraryFailure)) {
        return engine;
    }
    engine = ScanEngine();
#else
    const std::string libraryFailure;
#endif

    const char* candidates[] = {"clamscan", "clamdscan"};
    const ScanEngineKind kinds[] = {ScanEngineKind::ClamScan,
                                    ScanEngineKind::ClamDScan};
    for (std::size_t i = 0; i < 2; ++i) {
        const std::string path = findOnPath(candidates[i]);
        if (!path.empty()) {
            engine.available = true;
            engine.kind = kinds[i];
            engine.name = candidates[i];
            engine.executable = path;
            break;
        }
    }

    if (!engine.available) {
        engine.unavailableReason =
            "no ClamAV engine available (no libclamav database and no "
            "clamscan/clamdscan executable found on PATH)";
        if (!libraryFailure.empty()) {
            engine.unavailableReason += ": " + libraryFailure;
        }
        return engine;
    }

    // Signature directory: honour CLAMAV_DATADIR, else the usual locations.
    const char* dataDir = std::getenv("CLAMAV_DATADIR");
    const char* dirs[] = {dataDir, "/var/lib/clamav", "/usr/local/share/clamav",
                          "/var/lib/clamav-unofficial"};
    for (std::size_t i = 0; i < sizeof(dirs) / sizeof(dirs[0]); ++i) {
        if (dirs[i] == NULL || dirs[i][0] == '\0') {
            continue;
        }
        if (access(dirs[i], R_OK) == 0) {
            engine.databaseDir = dirs[i];
            break;
        }
    }

    // Query the version to learn the signature revision and its age.
    std::vector<std::string> argv;
    argv.push_back(engine.executable);
    argv.push_back("--version");

    std::string output;
    int exitCode = -1;
    if (runProcess(argv, 60, output, exitCode) && exitCode == 0) {
        const std::vector<std::string> lines = splitLines(output);
        for (std::size_t i = 0; i < lines.size(); ++i) {
            if (lines[i].compare(0, 7, "ClamAV ") == 0) {
                parseVersionLine(lines[i], engine);
                break;
            }
        }
    }

    if (!engine.signatureDate.empty()) {
        std::time_t signatureTime = 0;
        if (parseSignatureDate(engine.signatureDate, signatureTime)) {
            const std::int64_t ageSeconds =
                static_cast<std::int64_t>(std::time(NULL)) -
                static_cast<std::int64_t>(signatureTime);
            engine.signatureAgeDays = ageSeconds / 86400;
            engine.signatureOutdated =
                engine.signatureAgeDays > kSignatureMaxAgeDays;
        }
    }

    return engine;
}

ScanResult scanPath(const ScanEngine& engine, const std::string& target,
                    const ScanOptions& options) {
    ScanResult result;
    result.target = target;

    if (!engine.available) {
        result.error = engine.unavailableReason.empty()
                           ? std::string("ClamAV is not available")
                           : engine.unavailableReason;
        return result;
    }
    if (target.empty()) {
        result.error = "no scan target given";
        return result;
    }

#ifdef SYSINFO_HAVE_LIBCLAMAV
    if (engine.usingLibrary) {
        return scanPathWithLibrary(engine, target, options);
    }
#endif

    std::vector<std::string> argv;
    argv.push_back(engine.executable);
    if (options.recursive) {
        argv.push_back("-r");
    }
    if (options.removeInfected) {
        argv.push_back("--remove");
    }
    if (!options.quarantineDir.empty()) {
        argv.push_back("--move=" + options.quarantineDir);
    }
    if (options.maxFileSizeBytes > 0) {
        std::ostringstream size;
        size << "--max-filesize=" << options.maxFileSizeBytes;
        argv.push_back(size.str());
    }
    argv.push_back("--");
    argv.push_back(target);

    const std::uint32_t timeout =
        options.timeoutSeconds > 0 ? options.timeoutSeconds
                                   : kDefaultTimeoutSeconds;

    std::string output;
    int exitCode = -1;
    if (!runProcess(argv, timeout, output, exitCode)) {
        result.error = "could not run " + engine.name +
                       " (spawn failed or the scan timed out)";
        return result;
    }

    // clamscan/clamdscan: 0 = clean, 1 = threats found, 2 = error.
    result.exitCode = exitCode;
    if (exitCode != 0 && exitCode != 1) {
        result.error = "scanner reported an error (exit code " +
                       std::to_string(exitCode) + ")";
        const std::vector<std::string> lines = splitLines(output);
        for (std::size_t i = 0; i < lines.size(); ++i) {
            if (lines[i].compare(0, 5, "ERROR") == 0 ||
                lines[i].find("ERROR:") != std::string::npos) {
                result.error += ": " + lines[i];
                break;
            }
        }
        return result;
    }

    const std::vector<std::string> lines = splitLines(output);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const std::string& line = lines[i];
        // Threat lines look like "/path/file: Eicar-Test-Signature FOUND".
        const std::string marker = " FOUND";
        if (line.size() <= marker.size() ||
            line.compare(line.size() - marker.size(), marker.size(), marker) !=
                0) {
            continue;
        }
        const std::string body = line.substr(0, line.size() - marker.size());
        const std::size_t separator = body.rfind(": ");
        if (separator == std::string::npos) {
            continue;
        }
        ScanFinding finding;
        finding.path = body.substr(0, separator);
        finding.signature = trim(body.substr(separator + 2));
        if (!finding.path.empty()) {
            result.findings.push_back(finding);
        }
    }

    summaryValue(lines, "Scanned files", result.scannedFiles);
    summaryValue(lines, "Scanned directories", result.scannedDirectories);
    summaryValue(lines, "Infected files", result.infectedFiles);
    summaryDouble(lines, "Data scanned", result.dataScannedMiB);

    if (result.infectedFiles == 0 && !result.findings.empty()) {
        result.infectedFiles = result.findings.size();
    }
    result.infected = result.infectedFiles > 0 || !result.findings.empty();
    result.valid = true;
    return result;
}

}  // namespace sysinfo
