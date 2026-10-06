// sysinfo - ClamAV anti-virus integration
//
// Turns the system information report into a security report: it detects the
// ClamAV engine available on the machine, reports the state of its virus
// signature database and, on request, runs an on-demand scan of a file or
// directory tree.
//
// Two engines are supported, in order of preference:
//
//   * libclamav - the ClamAV engine library, loaded in-process and driven
//     through its C API (cl_engine_new/cl_load/cl_scanfile_ex). This is the
//     full integration: it works without the clamscan executable, keeps the
//     signature database in memory across scans and reports the signature
//     count. It is enabled automatically by CMake, which downloads and
//     unpacks the library into third_party/clamav when it is missing.
//   * clamscan/clamdscan - the command line scanner, executed as a child
//     process whose report is parsed. Used as a fallback when the build was
//     made without libclamav (SYSINFO_USE_CLAMAV=OFF) or when the library has
//     no usable signature database.

#ifndef SYSINFO_CLAMAV_SCAN_H
#define SYSINFO_CLAMAV_SCAN_H

#include <cstdint>
#include <string>
#include <vector>

namespace sysinfo {

// Which ClamAV front end is used to run an on-demand scan.
enum class ScanEngineKind {
    None,       // no ClamAV engine found on this system
    LibClamAV,  // the engine library, driven through its C API
    ClamScan,   // standalone scanner (/usr/bin/clamscan)
    ClamDScan,  // daemon client (/usr/bin/clamdscan)
};

// State of the ClamAV installation detected on the system.
struct ScanEngine {
    bool available = false;
    ScanEngineKind kind = ScanEngineKind::None;

    std::string name;        // "libclamav" / "clamscan" / "clamdscan"
    std::string executable;  // resolved path of the scanner executable
    std::string databaseDir; // signature directory, e.g. /var/lib/clamav

    std::string engineVersion;     // e.g. "1.5.4"
    std::string signatureVersion;  // signature revision, e.g. "27330"
    std::string signatureDate;     // raw date as printed by --version
    std::int64_t signatureAgeDays = -1;  // -1 when the date is unknown
    bool signatureOutdated = false;      // age above the freshness threshold

    // ---- libclamav specific (kind == LibClamAV) ----
    bool usingLibrary = false;      // scans run in-process through libclamav
    std::string libraryPath;        // resolved libclamav shared object
    std::uint64_t signatureCount = 0;  // signatures loaded into the engine
    std::string functionalLevel;    // ClamAV functional level, e.g. "129"

    // Human readable summary of why no engine is available (empty when one
    // was found).
    std::string unavailableReason;
};

// A single detected threat.
struct ScanFinding {
    std::string path;       // file that matched a signature
    std::string signature;  // signature name, e.g. "Eicar-Test-Signature"
};

// How a requested scan should behave.
struct ScanOptions {
    bool recursive = true;
    bool removeInfected = false;    // delete infected files (clamscan --remove)
    std::string quarantineDir;      // move infected files here when not empty
    std::uint64_t maxFileSizeBytes = 0;  // 0 keeps the ClamAV default
    std::uint32_t timeoutSeconds = 900;  // abort a runaway scan
};

// Result of one on-demand scan.
struct ScanResult {
    bool valid = false;   // the scanner ran and produced a report
    bool infected = false;
    std::string target;

    std::uint64_t scannedFiles = 0;
    std::uint64_t scannedDirectories = 0;
    std::uint64_t infectedFiles = 0;
    double dataScannedMiB = 0.0;

    std::vector<ScanFinding> findings;

    int exitCode = -1;
    std::string error;  // non-empty when the scan could not be completed
};

// Look for clamscan/clamdscan on PATH and query its version. When nothing is
// found the returned engine has available == false and unavailableReason set.
ScanEngine detectScanEngine();

// Run an on-demand scan of `target`. `engine` must come from
// detectScanEngine(); when it is not available the result carries
// valid == false and an explanatory error.
ScanResult scanPath(const ScanEngine& engine, const std::string& target,
                    const ScanOptions& options);

}  // namespace sysinfo

#endif  // SYSINFO_CLAMAV_SCAN_H
