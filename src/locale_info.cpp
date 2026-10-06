// sysinfo - system language / locale detection implementation

#include "sysinfo/locale_info.h"

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace sysinfo {

namespace {

const char* kLocaleFiles[] = {
    "/etc/default/locale",  // Debian / Ubuntu
    "/etc/locale.conf",     // systemd / Arch / Fedora
    "/etc/sysconfig/i18n",  // older Red Hat family
};

std::string trim(const std::string& text) {
    const std::string::size_type begin = text.find_first_not_of(" \t\r\n\"'");
    if (begin == std::string::npos) {
        return std::string();
    }
    const std::string::size_type end = text.find_last_not_of(" \t\r\n\"'");
    return text.substr(begin, end - begin + 1);
}

std::string toUpper(std::string text) {
    for (char& c : text) {
        if (c >= 'a' && c <= 'z') {
            c = static_cast<char>(c - 'a' + 'A');
        }
    }
    return text;
}

std::string toLower(std::string text) {
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

// "zh_CN.UTF-8" -> "zh_CN", "zh-Hans-CN@euro" -> "zh-Hans-CN"
std::string stripCodesetAndModifier(const std::string& locale) {
    std::string value = locale;
    const std::string::size_type dot = value.find('.');
    if (dot != std::string::npos) {
        value.erase(dot);
    }
    const std::string::size_type at = value.find('@');
    if (at != std::string::npos) {
        value.erase(at);
    }
    return trim(value);
}

// A value counts as "set" when it is neither empty nor the POSIX default.
bool isUsableLocale(const std::string& value) {
    const std::string upper = toUpper(trim(value));
    return !upper.empty() && upper != "C" && upper != "POSIX";
}

// Read KEY=value (or KEY="value") entries from a locale configuration file.
std::string readKeyFromFile(const std::string& path, const std::string& key) {
    std::ifstream in(path.c_str());
    if (!in) {
        return std::string();
    }

    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::string::size_type eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        if (trim(line.substr(0, eq)) == key) {
            return trim(line.substr(eq + 1));
        }
    }
    return std::string();
}

// /etc/sysconfig/i18n stores the locale in LANG or LC_ALL; systemd and Debian
// use LANG. LC_ALL/LANGUAGE are honoured too when present.
std::string readFromLocaleFiles() {
    static const char* kKeys[] = {"LANGUAGE", "LC_ALL", "LANG"};
    for (const char* file : kLocaleFiles) {
        for (const char* key : kKeys) {
            const std::string value = readKeyFromFile(file, key);
            if (isUsableLocale(value)) {
                return value;
            }
        }
    }
    return std::string();
}

bool localeIsUtf8(const std::string& locale) {
    const std::string upper = toUpper(locale);
    return upper.find("UTF-8") != std::string::npos ||
           upper.find("UTF8") != std::string::npos;
}

}  // namespace

Language languageFromLocale(const std::string& locale) {
    const std::string value = toLower(stripCodesetAndModifier(locale));
    if (value.empty()) {
        return Language::English;
    }

    // Normalize the separator so "zh-Hans-CN" and "zh_CN" behave the same.
    std::string normalized = value;
    for (char& c : normalized) {
        if (c == '_') {
            c = '-';
        }
    }

    const std::string::size_type dash = normalized.find('-');
    const std::string primary =
        dash == std::string::npos ? normalized : normalized.substr(0, dash);

    if (primary == "zh" || primary == "chinese" || primary == "cn") {
        return Language::Chinese;
    }
    return Language::English;
}

std::string languageName(Language language) {
    switch (language) {
        case Language::Chinese:
            return "Chinese";
        case Language::English:
        default:
            return "English";
    }
}

std::string languageNativeName(Language language) {
    switch (language) {
        case Language::Chinese:
            return "中文";
        case Language::English:
        default:
            return "English";
    }
}

LocaleInfo collectLocaleInfo(const std::string& override) {
    LocaleInfo info;

    if (!override.empty()) {
        info.locale = trim(override);
        info.source = "command line";
    }

    // Environment variables in POSIX priority order.
    if (info.locale.empty()) {
        static const char* kEnvVars[] = {"LANGUAGE", "LC_ALL", "LC_MESSAGES",
                                         "LANG"};
        for (const char* var : kEnvVars) {
            const char* raw = std::getenv(var);
            if (raw == nullptr) {
                continue;
            }
            const std::string value = trim(raw);
            if (!value.empty()) {
                // Recorded even when it is "C", so the report can show what the
                // environment asked for.
                info.candidates.push_back(std::string(var) + "=" + value);
            }
            if (info.locale.empty() && isUsableLocale(value)) {
                info.locale = value;
                info.source = std::string("env ") + var;
            }
        }
    }

    if (info.locale.empty()) {
        const std::string fromFile = readFromLocaleFiles();
        if (!fromFile.empty()) {
            info.locale = fromFile;
            info.source = "system locale config";
        }
    }

    if (info.locale.empty()) {
        info.locale = "C";
        info.source = "default (C)";
    }

    const std::string base = stripCodesetAndModifier(info.locale);
    const std::string::size_type dash = base.find_first_of("-_");
    info.languageCode =
        toLower(dash == std::string::npos ? base : base.substr(0, dash));
    info.utf8 = localeIsUtf8(info.locale);

    // A locale value without an explicit codeset (e.g. "--lang=zh" or a
    // LANGUAGE list such as "zh_CN:en_US") inherits the codeset the
    // environment uses; otherwise the report would claim a non-UTF-8 terminal.
    if (!info.utf8 && info.locale.find('.') == std::string::npos &&
        isUsableLocale(info.locale)) {
        static const char* kCodesetVars[] = {"LC_ALL", "LC_CTYPE", "LANG"};
        for (const char* var : kCodesetVars) {
            const char* raw = std::getenv(var);
            if (raw != nullptr && localeIsUtf8(raw)) {
                info.utf8 = true;
                break;
            }
        }
    }

    info.uiLanguage = languageFromLocale(info.locale);
    info.valid = !info.locale.empty();
    return info;
}

}  // namespace sysinfo
