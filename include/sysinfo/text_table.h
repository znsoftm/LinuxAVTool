// sysinfo - minimal fixed-width table renderer
//
// Shared by the plain text report and the interactive interface. Column widths
// are measured in terminal columns (see displayWidth() in i18n.h) rather than
// bytes, so CJK labels stay aligned.

#ifndef SYSINFO_TEXT_TABLE_H
#define SYSINFO_TEXT_TABLE_H

#include <string>
#include <utility>
#include <vector>

namespace sysinfo {

struct TextTable {
    std::vector<std::string> headers;
    std::vector<std::vector<std::string>> rows;

    void addRow(std::vector<std::string> cells) {
        rows.push_back(std::move(cells));
    }

    // Render the table with ASCII borders. Every line ends with '\n'.
    std::string render() const;
};

// Split `text` (as produced by TextTable::render()) into trimmed lines, with
// the trailing empty line dropped.
std::vector<std::string> splitRenderedLines(const std::string& text);

}  // namespace sysinfo

#endif  // SYSINFO_TEXT_TABLE_H
