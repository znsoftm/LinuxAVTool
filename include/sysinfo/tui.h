// sysinfo - interactive terminal interface
//
// Renders the same information as the plain report in a full screen terminal
// interface: one tab per section, keyboard navigation, an animated progress
// indicator while information is collected and while a ClamAV scan runs.
//
// The interface uses raw ANSI escape sequences and termios directly, so it has
// no dependency on ncurses (which is not installed everywhere).

#ifndef SYSINFO_TUI_H
#define SYSINFO_TUI_H

#include <string>

#include "sysinfo/clamav_scan.h"
#include "sysinfo/locale_info.h"

namespace sysinfo {

struct TuiOptions {
    bool scanRequested = false;
    std::string scanTarget;
    ScanOptions scanOptions;
};

// Run the interactive interface until the user quits. Returns the process exit
// code: 0 for a report / clean scan, 1 when threats were found, 2 when a
// requested scan could not be completed.
int runTui(const LocaleInfo& locale, const TuiOptions& options);

}  // namespace sysinfo

#endif  // SYSINFO_TUI_H
