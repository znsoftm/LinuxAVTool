// sysinfo - report content builder implementation

#include "sysinfo/report.h"

#include <iomanip>
#include <sstream>

#include "sysinfo/text_table.h"

namespace sysinfo {

namespace {

// Strip a trailing newline left by a section heading builder.
void appendTitle(std::vector<std::string>& lines, const std::string& title) {
    lines.push_back("== " + title + " ==");
}

void appendLines(std::vector<std::string>& out,
                 const std::vector<std::string>& lines) {
    out.insert(out.end(), lines.begin(), lines.end());
}

}  // namespace

std::string formatBytes(std::uint64_t bytes) {
    static const char* kUnits[] = {"B", "KiB", "MiB", "GiB", "TiB", "PiB"};
    const std::size_t kUnitCount = sizeof(kUnits) / sizeof(kUnits[0]);

    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < kUnitCount) {
        value /= 1024.0;
        ++unit;
    }

    std::ostringstream out;
    out << std::fixed << std::setprecision(unit == 0 ? 0 : 2) << value << ' '
        << kUnits[unit];
    return out.str();
}

std::string formatPercent(double value) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(1) << value << " %";
    return out.str();
}

std::string reportTitleLine(const Strings& s) {
    return std::string("sysinfo 0.1.0 - ") + s.reportTitleSuffix;
}

std::string reportGeneratedLine(const Strings& s) {
    return std::string(s.generatedPrefix) + __DATE__ + " " + __TIME__;
}

std::vector<std::string> languageSectionLines(const LocaleInfo& loc,
                                              const Strings& s) {
    std::vector<std::string> lines;
    appendTitle(lines, s.sectionLanguage);

    TextTable table;
    table.headers = {s.colMetric, s.colValue};
    table.addRow({s.rowLocale, loc.locale});
    table.addRow({s.rowLanguage,
                  languageName(loc.uiLanguage) + " (" +
                      languageNativeName(loc.uiLanguage) + ")"});
    table.addRow({s.rowCodeset, loc.utf8 ? s.valueUtf8 : s.valueNonUtf8});
    table.addRow({s.rowSource, loc.source});

    if (!loc.candidates.empty()) {
        std::string env;
        for (std::size_t i = 0; i < loc.candidates.size(); ++i) {
            if (i != 0) {
                env += ", ";
            }
            env += loc.candidates[i];
        }
        table.addRow({s.rowEnvironment, env});
    }
    appendLines(lines, splitRenderedLines(table.render()));
    return lines;
}

std::vector<std::string> memorySectionLines(const MemoryInfo& mem,
                                            const Strings& s) {
    std::vector<std::string> lines;
    appendTitle(lines, s.sectionMemory);

    if (!mem.valid) {
        lines.push_back(std::string(s.msgUnavailablePrefix) + mem.sourcePath +
                        s.msgUnavailableSuffix);
        return lines;
    }

    TextTable table;
    table.headers = {s.colMetric, s.colValue, s.colPercent};
    table.addRow({s.rowSource, mem.sourcePath, "-"});
    table.addRow({s.rowTotal, formatBytes(mem.totalBytes), "-"});
    table.addRow({s.rowUsed, formatBytes(mem.usedBytes),
                  formatPercent(mem.usedPercent())});
    table.addRow({s.rowFree, formatBytes(mem.freeBytes), "-"});
    table.addRow({s.rowAvailable, formatBytes(mem.availableBytes), "-"});
    table.addRow({s.rowBuffers, formatBytes(mem.buffersBytes), "-"});
    table.addRow({s.rowCached, formatBytes(mem.cachedBytes), "-"});
    table.addRow({s.rowSwapTotal, formatBytes(mem.swapTotalBytes), "-"});
    table.addRow({s.rowSwapUsed, formatBytes(mem.swapUsedBytes),
                  formatPercent(mem.swapUsedPercent())});
    table.addRow({s.rowSwapFree, formatBytes(mem.swapFreeBytes), "-"});
    appendLines(lines, splitRenderedLines(table.render()));
    return lines;
}

std::vector<std::string> diskSectionLines(const DiskInfo& disk,
                                          const Strings& s) {
    std::vector<std::string> lines;
    appendTitle(lines, s.sectionDisks);

    if (!disk.valid) {
        lines.push_back(s.msgNoFilesystems);
        return lines;
    }

    TextTable summary;
    summary.headers = {s.colMetric, s.colValue};
    summary.addRow({s.rowFilesystems, std::to_string(disk.filesystems.size())});
    summary.addRow({s.rowTotal, formatBytes(disk.totalBytes)});
    summary.addRow({s.rowUsed, formatBytes(disk.usedBytes) + " (" +
                                   formatPercent(disk.usedPercent()) + ")"});
    summary.addRow({s.rowAvailable, formatBytes(disk.availableBytes)});
    appendLines(lines, splitRenderedLines(summary.render()));

    lines.push_back(std::string());

    TextTable table;
    table.headers = {s.colMountPoint, s.colDevice, s.colType, s.colUsed,
                     s.colSize, s.colUsedPercent};
    for (std::size_t i = 0; i < disk.filesystems.size(); ++i) {
        const FilesystemInfo& fs = disk.filesystems[i];
        table.addRow({fs.mountPoint,
                      fs.device,
                      fs.fsType,
                      formatBytes(fs.usedBytes),
                      formatBytes(fs.totalBytes),
                      formatPercent(fs.usedPercent())});
    }
    appendLines(lines, splitRenderedLines(table.render()));
    return lines;
}

std::vector<std::string> securitySectionLines(const ScanEngine& engine,
                                              bool scanned,
                                              const ScanResult& result,
                                              const ScanOptions& options,
                                              const Strings& s) {
    std::vector<std::string> lines;
    appendTitle(lines, s.sectionSecurity);

    TextTable engineTable;
    engineTable.headers = {s.colMetric, s.colValue};
    if (engine.available) {
        engineTable.addRow({s.rowEngine, engine.name});
        const std::string& source =
            engine.usingLibrary ? engine.libraryPath : engine.executable;
        engineTable.addRow({s.rowSource, source.empty() ? "-" : source});
        engineTable.addRow({s.rowEngineVersion,
                            engine.engineVersion.empty() ? "-"
                                                         : engine.engineVersion});
        engineTable.addRow({s.rowSignatureVersion,
                            engine.signatureVersion.empty()
                                ? "-"
                                : engine.signatureVersion});
        engineTable.addRow({s.rowSignatureDate,
                            engine.signatureDate.empty() ? "-"
                                                         : engine.signatureDate});
        if (engine.signatureCount > 0) {
            engineTable.addRow({s.rowSignatureCount,
                                std::to_string(engine.signatureCount)});
        }

        std::string age = s.msgSignaturesUnknown;
        if (engine.signatureAgeDays >= 0) {
            std::ostringstream text;
            text << engine.signatureAgeDays << ' ' << s.valueDays;
            if (engine.signatureOutdated) {
                text << " (" << s.msgSignaturesOutdated << ")";
            } else {
                text << " (" << s.msgSignaturesFresh << ")";
            }
            age = text.str();
        }
        engineTable.addRow({s.rowSignatureAge, age});
        engineTable.addRow({s.rowDatabaseDir,
                            engine.databaseDir.empty() ? "-"
                                                       : engine.databaseDir});
    } else {
        engineTable.addRow({s.rowEngine, s.msgNoScanEngine});
    }
    appendLines(lines, splitRenderedLines(engineTable.render()));

    if (!scanned) {
        return lines;
    }

    lines.push_back(std::string());

    TextTable scanTable;
    scanTable.headers = {s.colMetric, s.colValue};
    scanTable.addRow({s.rowScanTarget, result.target});
    scanTable.addRow({s.rowScanEngine, engine.name});

    if (!result.valid) {
        scanTable.addRow({s.rowScanStatus, s.msgScanFailed});
        scanTable.addRow({s.rowAction, result.error});
        appendLines(lines, splitRenderedLines(scanTable.render()));
        return lines;
    }

    scanTable.addRow({s.rowFilesScanned, std::to_string(result.scannedFiles)});
    scanTable.addRow({s.rowDirectoriesScanned,
                      std::to_string(result.scannedDirectories)});

    std::ostringstream data;
    data << std::fixed << std::setprecision(2) << result.dataScannedMiB
         << " MiB";
    scanTable.addRow({s.rowDataScanned, data.str()});
    scanTable.addRow({s.rowThreatsFound, std::to_string(result.infectedFiles)});
    scanTable.addRow({s.rowScanStatus,
                      result.infected ? s.msgScanInfected : s.msgScanClean});

    const char* action = s.msgScanActionNone;
    if (options.removeInfected) {
        action = s.msgScanActionRemoved;
    } else if (!options.quarantineDir.empty()) {
        action = s.msgScanActionQuarantined;
    }
    scanTable.addRow({s.rowAction, action});
    appendLines(lines, splitRenderedLines(scanTable.render()));

    if (!result.findings.empty()) {
        lines.push_back(std::string());
        TextTable findings;
        findings.headers = {s.colThreat, s.colSignature};
        for (std::size_t i = 0; i < result.findings.size(); ++i) {
            findings.addRow({result.findings[i].path,
                             result.findings[i].signature});
        }
        appendLines(lines, splitRenderedLines(findings.render()));
    }
    return lines;
}

}  // namespace sysinfo
