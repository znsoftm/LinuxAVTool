// sysinfo - system language / locale detection
//
// Determines the language the user's environment asks for (e.g. zh_CN.UTF-8)
// so the report can be printed in the matching language. Priority follows the
// POSIX convention: LANGUAGE, LC_ALL, LC_MESSAGES, LANG, then the system wide
// configuration files /etc/default/locale and /etc/locale.conf.

#ifndef SYSINFO_LOCALE_INFO_H
#define SYSINFO_LOCALE_INFO_H

#include <string>
#include <vector>

namespace sysinfo {

// Languages the report can be rendered in.
enum class Language {
    English,
    Chinese,
};

// Language / locale snapshot of the running system.
struct LocaleInfo {
    bool valid = false;

    std::string locale;       // effective locale, e.g. "zh_CN.utf8"
    std::string languageCode; // primary language subtag, e.g. "zh"
    std::string source;       // where the locale came from, e.g. "env LANG"
    bool utf8 = false;        // locale declares a UTF-8 codeset
    Language uiLanguage = Language::English;

    // All locale values that were inspected, in priority order.
    std::vector<std::string> candidates;
};

// Map a locale string ("zh_CN.UTF-8", "zh-Hans-CN", "zh", "en_US") to the
// report language. Unknown locales fall back to English.
Language languageFromLocale(const std::string& locale);

// Short language name used in the report, e.g. "Chinese" / "English".
std::string languageName(Language language);

// Localized language name, e.g. "中文" / "English".
std::string languageNativeName(Language language);

// Collect the language/locale information. `override` (when not empty) wins
// over the environment; pass an empty string for auto detection.
LocaleInfo collectLocaleInfo(const std::string& override);

}  // namespace sysinfo

#endif  // SYSINFO_LOCALE_INFO_H
