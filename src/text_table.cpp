// sysinfo - minimal fixed-width table renderer implementation

#include "sysinfo/text_table.h"

#include <algorithm>
#include <sstream>

#include "sysinfo/i18n.h"

namespace sysinfo {

std::string TextTable::render() const {
    std::ostringstream out;

    // Widths are measured in terminal columns, not bytes, so CJK labels stay
    // aligned.
    std::vector<std::size_t> width(headers.size(), 0);
    for (std::size_t i = 0; i < headers.size(); ++i) {
        width[i] = displayWidth(headers[i]);
    }
    for (std::size_t r = 0; r < rows.size(); ++r) {
        const std::vector<std::string>& row = rows[r];
        for (std::size_t i = 0; i < row.size() && i < width.size(); ++i) {
            width[i] = std::max(width[i], displayWidth(row[i]));
        }
    }

    const std::size_t columns = headers.size();
    const auto rule = [&](char left, char mid, char right) {
        out << left;
        for (std::size_t i = 0; i < columns; ++i) {
            out << std::string(width[i] + 2, '-');
            out << (i + 1 == columns ? right : mid);
        }
        out << '\n';
    };
    const auto line = [&](const std::vector<std::string>& cells) {
        out << '|';
        for (std::size_t i = 0; i < columns; ++i) {
            const std::string cell = i < cells.size() ? cells[i] : std::string();
            out << ' ' << padToDisplayWidth(cell, width[i]) << " |";
        }
        out << '\n';
    };

    rule('+', '+', '+');
    line(headers);
    rule('+', '+', '+');
    for (std::size_t r = 0; r < rows.size(); ++r) {
        line(rows[r]);
    }
    rule('+', '+', '+');

    return out.str();
}

std::vector<std::string> splitRenderedLines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream stream(text);
    std::string line;
    while (std::getline(stream, line)) {
        if (!line.empty() && line[line.size() - 1] == '\r') {
            line.erase(line.size() - 1);
        }
        lines.push_back(line);
    }
    return lines;
}

}  // namespace sysinfo
