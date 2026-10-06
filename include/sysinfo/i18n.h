// sysinfo - minimal localization layer
//
// Holds the report strings for every supported language plus helpers for
// rendering text whose width must be measured in terminal columns (CJK
// characters occupy two columns, so byte or code unit counts are wrong).

#ifndef SYSINFO_I18N_H
#define SYSINFO_I18N_H

#include <cstddef>
#include <string>

#include "sysinfo/locale_info.h"

namespace sysinfo {

// Every user visible string of the report. All members are literals owned by
// the translation table returned by stringsFor().
struct Strings {
    // Header
    const char* reportTitleSuffix;  // "system information report" / "系统信息报告"
    const char* generatedPrefix;    // "Generated: " / "生成时间："

    // Section titles
    const char* sectionMemory;
    const char* sectionDisks;
    const char* sectionLanguage;
    const char* sectionSecurity;

    // Table headers
    const char* colMetric;
    const char* colValue;
    const char* colPercent;
    const char* colMountPoint;
    const char* colDevice;
    const char* colType;
    const char* colUsed;
    const char* colSize;
    const char* colUsedPercent;
    const char* colThreat;
    const char* colSignature;

    // Row labels
    const char* rowSource;
    const char* rowTotal;
    const char* rowUsed;
    const char* rowFree;
    const char* rowAvailable;
    const char* rowBuffers;
    const char* rowCached;
    const char* rowSwapTotal;
    const char* rowSwapUsed;
    const char* rowSwapFree;
    const char* rowFilesystems;
    const char* rowLocale;
    const char* rowLanguage;
    const char* rowNativeName;
    const char* rowCodeset;
    const char* rowEnvironment;

    // Security / anti-virus rows
    const char* rowEngine;
    const char* rowEngineVersion;
    const char* rowSignatureVersion;
    const char* rowSignatureDate;
    const char* rowSignatureAge;
    const char* rowSignatureCount;
    const char* rowDatabaseDir;
    const char* rowScanTarget;
    const char* rowScanEngine;
    const char* rowFilesScanned;
    const char* rowDirectoriesScanned;
    const char* rowDataScanned;
    const char* rowThreatsFound;
    const char* rowScanStatus;
    const char* rowAction;

    // Messages
    const char* msgUnavailablePrefix;  // "unavailable (source: " / "不可用（来源："
    const char* msgUnavailableSuffix;  // ")" / "）"
    const char* msgNoFilesystems;
    const char* msgUnknownOption;  // printed before the offending option
    const char* msgInvalidLanguage;
    const char* msgHelpUsage;
    const char* msgHelpOptions;
    const char* msgHelpLang;
    const char* msgHelpHelp;

    // Security / scan messages
    const char* msgNoScanEngine;      // ClamAV is missing, no scan performed
    const char* msgScanClean;
    const char* msgScanInfected;
    const char* msgScanFailed;
    const char* msgScanSkipped;
    const char* msgSignaturesOutdated;
    const char* msgSignaturesFresh;
    const char* msgSignaturesUnknown;
    const char* msgHelpScan;
    const char* msgHelpRemove;
    const char* msgHelpQuarantine;
    const char* msgScanActionRemoved;
    const char* msgScanActionQuarantined;
    const char* msgScanActionNone;
    const char* msgNoScanTarget;

    // Values
    const char* valueYes;
    const char* valueNo;
    const char* valueUtf8;     // "UTF-8"
    const char* valueNonUtf8;  // "non-UTF-8" / "非 UTF-8"
    const char* valueDays;     // unit suffix, "d" / " 天"

    // Interactive interface (TUI)
    const char* uiTabMemory;
    const char* uiTabDisks;
    const char* uiTabSecurity;
    const char* uiTabLanguage;
    const char* uiCollecting;   // status text while information is gathered
    const char* uiScanning;     // status text while a scan runs
    const char* uiElapsed;      // "elapsed" prefix before the seconds count
    const char* uiReady;        // status text when idle
    const char* uiHint;         // bottom key hint
    const char* uiNoScanEngineHint;  // shown when 's' cannot do anything
    const char* msgHelpTui;
    const char* msgHelpPlain;
    const char* msgNotATerminal;
};

// Translation table for the given language (English is the fallback).
const Strings& stringsFor(Language language);

// Number of terminal columns `text` occupies when printed. Decodes UTF-8 and
// counts East Asian wide / fullwidth characters as two columns.
std::size_t displayWidth(const std::string& text);

// `text` padded with spaces on the right up to `width` display columns.
std::string padToDisplayWidth(const std::string& text, std::size_t width);

// The longest prefix of `text` that fits in `width` display columns. Never
// splits a UTF-8 sequence, so the result is always valid UTF-8.
std::string clipToDisplayWidth(const std::string& text, std::size_t width);

}  // namespace sysinfo

#endif  // SYSINFO_I18N_H
