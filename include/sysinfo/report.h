// sysinfo - report content builder
//
// Renders the collected system information into ready-to-print lines. Both the
// plain text report (main.cpp) and the interactive interface (tui.cpp) build
// their content from here, so the two views never drift apart.

#ifndef SYSINFO_REPORT_H
#define SYSINFO_REPORT_H

#include <string>
#include <vector>

#include "sysinfo/clamav_scan.h"
#include "sysinfo/disk_info.h"
#include "sysinfo/i18n.h"
#include "sysinfo/locale_info.h"
#include "sysinfo/memory_info.h"

namespace sysinfo {

// Header lines of the report ("sysinfo 0.1.0 - <suffix>", "Generated: ...").
std::string reportTitleLine(const Strings& s);
std::string reportGeneratedLine(const Strings& s);

// Lines of a single section, without the section title and without a trailing
// newline. The interactive interface shows one section per tab.
std::vector<std::string> languageSectionLines(const LocaleInfo& locale,
                                              const Strings& s);
std::vector<std::string> memorySectionLines(const MemoryInfo& memory,
                                            const Strings& s);
std::vector<std::string> diskSectionLines(const DiskInfo& disk,
                                          const Strings& s);

// `scanned` is true when a scan was requested and actually executed; when it is
// false only the scanner state is shown.
std::vector<std::string> securitySectionLines(const ScanEngine& engine,
                                              bool scanned,
                                              const ScanResult& result,
                                              const ScanOptions& options,
                                              const Strings& s);

// Byte count as a human readable string such as "15.6 GiB".
std::string formatBytes(std::uint64_t bytes);

// Ratio (0..100) as a string such as "80.9 %".
std::string formatPercent(double value);

}  // namespace sysinfo

#endif  // SYSINFO_REPORT_H
