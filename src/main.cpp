// sysinfo - system information and security inspection tool
//
// Entry point: collects and prints language, memory and disk information plus
// the state of the ClamAV anti-virus engine on Linux, and can run an on-demand
// virus scan of a path. The report is rendered in the language requested by
// the environment (LANG/LC_* or the system locale configuration), overridable
// with --lang.
//
// On a terminal the report is shown in an interactive full screen interface
// (see tui.cpp); with --plain, when stdout is not a terminal, or when the
// interface cannot be initialised, the classic plain text report is printed.

#include <iostream>
#include <string>
#include <vector>

#include "sysinfo/clamav_scan.h"
#include "sysinfo/disk_info.h"
#include "sysinfo/i18n.h"
#include "sysinfo/locale_info.h"
#include "sysinfo/memory_info.h"
#include "sysinfo/report.h"
#include "sysinfo/tui.h"

namespace {

// Accepts "en", "zh", "zh_CN", "en_US.UTF-8", "chinese", ...
bool parseLanguageCode(const std::string& code, sysinfo::Language& out) {
    std::string lower = code;
    for (char& c : lower) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    const auto startsWith = [&](const char* prefix) {
        return lower.compare(0, std::string(prefix).size(), prefix) == 0;
    };

    if (lower == "zh" || lower == "cn" || lower == "chinese" ||
        startsWith("zh_") || startsWith("zh-")) {
        out = sysinfo::Language::Chinese;
        return true;
    }
    if (lower == "en" || lower == "english" || startsWith("en_") ||
        startsWith("en-")) {
        out = sysinfo::Language::English;
        return true;
    }
    return false;
}

void printUsage(const sysinfo::Strings& s) {
    std::cout << s.msgHelpUsage << '\n'
              << s.msgHelpOptions << '\n'
              << s.msgHelpLang << '\n'
              << s.msgHelpScan << '\n'
              << s.msgHelpRemove << '\n'
              << s.msgHelpQuarantine << '\n'
              << s.msgHelpTui << '\n'
              << s.msgHelpPlain << '\n'
              << s.msgHelpHelp << '\n';
}

// Print the classic plain text report.
int runPlain(const sysinfo::LocaleInfo& locale,
             const sysinfo::ScanEngine& engine, bool scanRequested,
             const std::string& scanTarget, const sysinfo::ScanOptions& options) {
    const sysinfo::Strings& s = sysinfo::stringsFor(locale.uiLanguage);

    const sysinfo::MemoryInfo memory = sysinfo::collectMemoryInfo();
    const sysinfo::DiskInfo disk = sysinfo::collectDiskInfo();

    std::cout << sysinfo::reportTitleLine(s) << '\n';
    std::cout << sysinfo::reportGeneratedLine(s) << '\n';

    const auto printLines = [](const std::vector<std::string>& lines) {
        for (std::size_t i = 0; i < lines.size(); ++i) {
            std::cout << lines[i] << '\n';
        }
    };

    std::cout << '\n';
    printLines(sysinfo::languageSectionLines(locale, s));
    std::cout << '\n';
    printLines(sysinfo::memorySectionLines(memory, s));
    std::cout << '\n';
    printLines(sysinfo::diskSectionLines(disk, s));
    std::cout << '\n';

    sysinfo::ScanResult scanResult;
    scanResult.target = scanTarget;
    bool performedScan = false;
    if (scanRequested && engine.available && !scanTarget.empty()) {
        scanResult = sysinfo::scanPath(engine, scanTarget, options);
        performedScan = true;
    }
    printLines(sysinfo::securitySectionLines(engine, performedScan, scanResult,
                                             options, s));

    // Exit code mirrors the scan verdict so the tool can be scripted:
    // 0 = clean/report only, 1 = threats found, 2 = scan could not run.
    if (scanRequested && !engine.available) {
        return 0;
    }
    if (performedScan) {
        if (!scanResult.valid) {
            return 2;
        }
        if (scanResult.infected) {
            return 1;
        }
    }
    return 0;
}

}  // namespace

int main(int argc, char** argv) {
    sysinfo::LocaleInfo locale = sysinfo::collectLocaleInfo(std::string());

    // Resolve --lang first so that --help (and early option errors) are printed
    // in the language the user asked for, regardless of argument order.
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        std::string code;
        if (arg == "--lang" && i + 1 < argc) {
            code = argv[i + 1];
        } else if (arg.compare(0, 7, "--lang=") == 0) {
            code = arg.substr(7);
        } else {
            continue;
        }
        sysinfo::Language forced = sysinfo::Language::English;
        if (parseLanguageCode(code, forced)) {
            locale = sysinfo::collectLocaleInfo(code);
            locale.uiLanguage = forced;
        }
        break;
    }

    // The language used for early diagnostics (option errors, --help) is the
    // one detected from the environment.
    const sysinfo::Strings& envStrings = sysinfo::stringsFor(locale.uiLanguage);

    sysinfo::ScanOptions scanOptions;
    std::string scanTarget;
    bool scanRequested = false;

    int mode = 0;  // 0 = auto, 1 = force TUI, 2 = force plain

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(envStrings);
            return 0;
        }
        if (arg == "--tui") {
            mode = 1;
            continue;
        }
        if (arg == "--plain") {
            mode = 2;
            continue;
        }
        if (arg == "--scan" && i + 1 < argc) {
            scanTarget = argv[++i];
            scanRequested = true;
            continue;
        }
        if (arg.compare(0, 7, "--scan=") == 0) {
            scanTarget = arg.substr(7);
            scanRequested = true;
            continue;
        }
        if (arg == "--remove") {
            scanOptions.removeInfected = true;
            continue;
        }
        if (arg == "--quarantine" && i + 1 < argc) {
            scanOptions.quarantineDir = argv[++i];
            continue;
        }
        if (arg.compare(0, 13, "--quarantine=") == 0) {
            scanOptions.quarantineDir = arg.substr(13);
            continue;
        }
        if (arg == "--lang" && i + 1 < argc) {
            ++i;
            const std::string code = argv[i];
            sysinfo::Language forced = sysinfo::Language::English;
            if (!parseLanguageCode(code, forced)) {
                std::cerr << "sysinfo: " << envStrings.msgInvalidLanguage << code
                          << '\n';
                return 2;
            }
            locale = sysinfo::collectLocaleInfo(code);
            locale.uiLanguage = forced;
            continue;
        }
        if (arg.compare(0, 7, "--lang=") == 0) {
            const std::string code = arg.substr(7);
            sysinfo::Language forced = sysinfo::Language::English;
            if (!parseLanguageCode(code, forced)) {
                std::cerr << "sysinfo: " << envStrings.msgInvalidLanguage << code
                          << '\n';
                return 2;
            }
            locale = sysinfo::collectLocaleInfo(code);
            locale.uiLanguage = forced;
            continue;
        }
        std::cerr << "sysinfo: " << envStrings.msgUnknownOption << arg << '\n';
        printUsage(envStrings);
        return 2;
    }

    const sysinfo::Strings& s = sysinfo::stringsFor(locale.uiLanguage);

    // A scan is only meaningful with a target; --remove/--quarantine without
    // --scan falls back to the current working directory.
    if (!scanRequested &&
        (scanOptions.removeInfected || !scanOptions.quarantineDir.empty())) {
        scanTarget = ".";
        scanRequested = true;
    }

    sysinfo::TuiOptions tuiOptions;
    tuiOptions.scanRequested = scanRequested;
    tuiOptions.scanTarget = scanTarget;
    tuiOptions.scanOptions = scanOptions;

    if (mode != 2) {
        const int code = sysinfo::runTui(locale, tuiOptions);
        if (code >= 0) {
            return code;
        }
        if (mode == 1) {
            // The user explicitly asked for the interface but it cannot run
            // (not a terminal); say so before falling back.
            std::cerr << "sysinfo: " << s.msgNotATerminal << '\n';
        }
    }

    const sysinfo::ScanEngine engine = sysinfo::detectScanEngine();
    return runPlain(locale, engine, scanRequested, scanTarget, scanOptions);
}
