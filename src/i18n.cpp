// sysinfo - minimal localization layer implementation

#include "sysinfo/i18n.h"

#include <cstdint>

namespace sysinfo {

namespace {

const Strings kEnglish = {
    /* reportTitleSuffix */ "system information report",
    /* generatedPrefix    */ "Generated: ",

    /* sectionMemory   */ "Memory",
    /* sectionDisks    */ "Disks",
    /* sectionLanguage */ "Language",
    /* sectionSecurity */ "Security",

    /* colMetric       */ "Metric",
    /* colValue        */ "Value",
    /* colPercent      */ "Percent",
    /* colMountPoint   */ "Mount point",
    /* colDevice       */ "Device",
    /* colType         */ "Type",
    /* colUsed         */ "Used",
    /* colSize         */ "Size",
    /* colUsedPercent  */ "Used %",
    /* colThreat       */ "Threat",
    /* colSignature    */ "Signature",

    /* rowSource      */ "Source",
    /* rowTotal       */ "Total",
    /* rowUsed        */ "Used",
    /* rowFree        */ "Free",
    /* rowAvailable   */ "Available",
    /* rowBuffers     */ "Buffers",
    /* rowCached      */ "Cached",
    /* rowSwapTotal   */ "Swap total",
    /* rowSwapUsed    */ "Swap used",
    /* rowSwapFree    */ "Swap free",
    /* rowFilesystems */ "Filesystems",
    /* rowLocale      */ "Locale",
    /* rowLanguage    */ "Language",
    /* rowNativeName  */ "Native name",
    /* rowCodeset     */ "Codeset",
    /* rowEnvironment */ "Environment",

    /* rowEngine             */ "Engine",
    /* rowEngineVersion      */ "Engine version",
    /* rowSignatureVersion   */ "Signature version",
    /* rowSignatureDate      */ "Signature date",
    /* rowSignatureAge       */ "Signature age",
    /* rowSignatureCount     */ "Signatures loaded",
    /* rowDatabaseDir        */ "Signature database",
    /* rowScanTarget         */ "Scan target",
    /* rowScanEngine         */ "Scanner",
    /* rowFilesScanned       */ "Files scanned",
    /* rowDirectoriesScanned */ "Directories scanned",
    /* rowDataScanned        */ "Data scanned",
    /* rowThreatsFound       */ "Threats found",
    /* rowScanStatus         */ "Scan status",
    /* rowAction             */ "Action",

    /* msgUnavailablePrefix  */ "unavailable (source: ",
    /* msgUnavailableSuffix  */ ")",
    /* msgNoFilesystems      */ "no mounted filesystem could be inspected",
    /* msgUnknownOption      */ "unknown option: ",
    /* msgInvalidLanguage    */ "unsupported language code: ",
    /* msgHelpUsage          */ "Usage: sysinfo [options] [path]",
    /* msgHelpOptions        */ "Options:",
    /* msgHelpLang           */ "  --lang=<code>   force report language (en, zh), default: auto detect",
    /* msgHelpHelp           */ "  --help          show this help and exit",

    /* msgNoScanEngine         */ "ClamAV is not installed, virus scanning is unavailable",
    /* msgScanClean            */ "clean",
    /* msgScanInfected         */ "infected",
    /* msgScanFailed           */ "scan failed",
    /* msgScanSkipped          */ "not performed",
    /* msgSignaturesOutdated   */ "outdated, please update (freshclam)",
    /* msgSignaturesFresh      */ "up to date",
    /* msgSignaturesUnknown    */ "unknown",
    /* msgHelpScan             */ "  --scan=<path>   run a ClamAV on-demand scan of <path>",
    /* msgHelpRemove           */ "  --remove        delete infected files during the scan",
    /* msgHelpQuarantine       */ "  --quarantine=<dir>  move infected files to <dir> during the scan",
    /* msgScanActionRemoved    */ "deleted",
    /* msgScanActionQuarantined*/ "quarantined",
    /* msgScanActionNone       */ "reported only",
    /* msgNoScanTarget         */ "no scan target given (use --scan=<path>)",

    /* valueYes */ "yes",
    /* valueNo  */ "no",
    /* valueUtf8    */ "UTF-8",
    /* valueNonUtf8 */ "non-UTF-8",
    /* valueDays    */ "days",

    /* uiTabMemory     */ "Memory",
    /* uiTabDisks      */ "Disks",
    /* uiTabSecurity   */ "Security",
    /* uiTabLanguage   */ "Language",
    /* uiCollecting    */ "Collecting system information",
    /* uiScanning      */ "Scanning",
    /* uiElapsed       */ "elapsed",
    /* uiReady         */ "Ready",
    /* uiHint          */ "Tab/Shift-Tab: switch  Up/Down: scroll  s: scan  r: refresh  q: quit",
    /* uiNoScanEngineHint */ "ClamAV not installed, nothing to scan",
    /* msgHelpTui      */ "  --tui           interactive terminal interface (default on a TTY)",
    /* msgHelpPlain    */ "  --plain         force the plain text report",
    /* msgNotATerminal */ "not a terminal, falling back to the plain report",
};

const Strings kChinese = {
    /* reportTitleSuffix */ "系统信息报告",
    /* generatedPrefix    */ "生成时间：",

    /* sectionMemory   */ "内存",
    /* sectionDisks    */ "磁盘",
    /* sectionLanguage */ "语言",
    /* sectionSecurity */ "安全",

    /* colMetric       */ "指标",
    /* colValue        */ "数值",
    /* colPercent      */ "百分比",
    /* colMountPoint   */ "挂载点",
    /* colDevice       */ "设备",
    /* colType         */ "类型",
    /* colUsed         */ "已用",
    /* colSize         */ "容量",
    /* colUsedPercent  */ "使用率",
    /* colThreat       */ "威胁文件",
    /* colSignature    */ "病毒特征",

    /* rowSource      */ "来源",
    /* rowTotal       */ "总计",
    /* rowUsed        */ "已用",
    /* rowFree        */ "空闲",
    /* rowAvailable   */ "可用",
    /* rowBuffers     */ "缓冲区",
    /* rowCached      */ "缓存",
    /* rowSwapTotal   */ "交换区总量",
    /* rowSwapUsed    */ "交换区已用",
    /* rowSwapFree    */ "交换区空闲",
    /* rowFilesystems */ "文件系统数",
    /* rowLocale      */ "区域设置",
    /* rowLanguage    */ "语言",
    /* rowNativeName  */ "本地名称",
    /* rowCodeset     */ "字符集",
    /* rowEnvironment */ "环境变量",

    /* rowEngine             */ "查杀引擎",
    /* rowEngineVersion      */ "引擎版本",
    /* rowSignatureVersion   */ "病毒库版本",
    /* rowSignatureDate      */ "病毒库日期",
    /* rowSignatureAge       */ "病毒库时长",
    /* rowSignatureCount     */ "已加载特征数",
    /* rowDatabaseDir        */ "病毒库路径",
    /* rowScanTarget         */ "扫描目标",
    /* rowScanEngine         */ "扫描程序",
    /* rowFilesScanned       */ "已扫描文件",
    /* rowDirectoriesScanned */ "已扫描目录",
    /* rowDataScanned        */ "扫描数据量",
    /* rowThreatsFound       */ "发现威胁",
    /* rowScanStatus         */ "扫描状态",
    /* rowAction             */ "处理方式",

    /* msgUnavailablePrefix  */ "不可用（来源：",
    /* msgUnavailableSuffix  */ "）",
    /* msgNoFilesystems      */ "未能检测到任何已挂载的文件系统",
    /* msgUnknownOption      */ "未知选项：",
    /* msgInvalidLanguage    */ "不支持的语言代码：",
    /* msgHelpUsage          */ "用法：sysinfo [选项] [路径]",
    /* msgHelpOptions        */ "选项：",
    /* msgHelpLang           */ "  --lang=<代码>   强制指定报告语言（en、zh），默认自动检测",
    /* msgHelpHelp           */ "  --help          显示本帮助并退出",

    /* msgNoScanEngine         */ "未安装 ClamAV，病毒查杀功能不可用",
    /* msgScanClean            */ "未发现病毒",
    /* msgScanInfected         */ "发现病毒",
    /* msgScanFailed           */ "扫描失败",
    /* msgScanSkipped          */ "未执行",
    /* msgSignaturesOutdated   */ "已过期，请运行 freshclam 更新",
    /* msgSignaturesFresh      */ "已是最新",
    /* msgSignaturesUnknown    */ "未知",
    /* msgHelpScan             */ "  --scan=<路径>   使用 ClamAV 对指定路径执行查杀",
    /* msgHelpRemove           */ "  --remove        扫描时直接删除被感染文件",
    /* msgHelpQuarantine       */ "  --quarantine=<目录>  扫描时将感染文件移动到隔离目录",
    /* msgScanActionRemoved    */ "已删除",
    /* msgScanActionQuarantined*/ "已隔离",
    /* msgScanActionNone       */ "仅报告",
    /* msgNoScanTarget         */ "未指定扫描目标（请使用 --scan=<路径>）",

    /* valueYes */ "是",
    /* valueNo  */ "否",
    /* valueUtf8    */ "UTF-8",
    /* valueNonUtf8 */ "非 UTF-8",
    /* valueDays    */ "天",

    /* uiTabMemory     */ "内存",
    /* uiTabDisks      */ "磁盘",
    /* uiTabSecurity   */ "安全",
    /* uiTabLanguage   */ "语言",
    /* uiCollecting    */ "正在采集系统信息",
    /* uiScanning      */ "正在扫描",
    /* uiElapsed       */ "已用",
    /* uiReady         */ "就绪",
    /* uiHint          */ "Tab/Shift-Tab：切换  ↑/↓：滚动  s：扫描  r：刷新  q：退出",
    /* uiNoScanEngineHint */ "未安装 ClamAV，无可用查杀引擎",
    /* msgHelpTui      */ "  --tui           交互式终端界面（终端下默认启用）",
    /* msgHelpPlain    */ "  --plain         强制输出纯文本报告",
    /* msgNotATerminal */ "非终端环境，已回退到纯文本报告",
};

// Number of bytes of the UTF-8 sequence starting with `lead` (0 when invalid).
std::size_t utf8SequenceLength(unsigned char lead) {
    if (lead < 0x80) {
        return 1;
    }
    if ((lead & 0xE0) == 0xC0) {
        return 2;
    }
    if ((lead & 0xF0) == 0xE0) {
        return 3;
    }
    if ((lead & 0xF8) == 0xF0) {
        return 4;
    }
    return 1;  // stray continuation byte: count it as one column
}

std::uint32_t decodeCodepoint(const std::string& text, std::size_t offset,
                              std::size_t length) {
    static const std::uint32_t kMasks[] = {0x7F, 0x1F, 0x0F, 0x07};
    std::uint32_t code = static_cast<unsigned char>(text[offset]) & kMasks[length - 1];
    for (std::size_t i = 1; i < length; ++i) {
        code = (code << 6) |
               (static_cast<unsigned char>(text[offset + i]) & 0x3F);
    }
    return code;
}

// True for characters rendered two columns wide in a terminal (CJK, Hangul,
// fullwidth forms, ...).
bool isWideCodepoint(std::uint32_t code) {
    return (code >= 0x1100 && code <= 0x115F) ||    // Hangul Jamo
           (code >= 0x2E80 && code <= 0x303E) ||    // CJK radicals / punctuation
           (code >= 0x3041 && code <= 0x33FF) ||    // Kana, CJK compatibility
           (code >= 0x3400 && code <= 0x4DBF) ||    // CJK ext A
           (code >= 0x4E00 && code <= 0x9FFF) ||    // CJK unified ideographs
           (code >= 0xA000 && code <= 0xA4CF) ||    // Yi
           (code >= 0xAC00 && code <= 0xD7A3) ||    // Hangul syllables
           (code >= 0xF900 && code <= 0xFAFF) ||    // CJK compatibility ideographs
           (code >= 0xFE30 && code <= 0xFE6F) ||    // CJK compatibility forms
           (code >= 0xFF00 && code <= 0xFF60) ||    // fullwidth forms
           (code >= 0xFFE0 && code <= 0xFFE6) ||
           (code >= 0x20000 && code <= 0x3FFFD);    // CJK ext B and beyond
}

// Zero width: combining marks and format characters.
bool isZeroWidthCodepoint(std::uint32_t code) {
    return (code >= 0x0300 && code <= 0x036F) ||
           (code >= 0x200B && code <= 0x200F) || (code == 0xFEFF);
}

}  // namespace

const Strings& stringsFor(Language language) {
    switch (language) {
        case Language::Chinese:
            return kChinese;
        case Language::English:
        default:
            return kEnglish;
    }
}

std::size_t displayWidth(const std::string& text) {
    std::size_t width = 0;
    std::size_t i = 0;
    while (i < text.size()) {
        const std::size_t length = utf8SequenceLength(
            static_cast<unsigned char>(text[i]));
        if (i + length > text.size()) {
            ++width;  // truncated sequence: count the raw byte
            break;
        }
        const std::uint32_t code = decodeCodepoint(text, i, length);
        if (!isZeroWidthCodepoint(code)) {
            width += isWideCodepoint(code) ? 2 : 1;
        }
        i += length;
    }
    return width;
}

std::string padToDisplayWidth(const std::string& text, std::size_t width) {
    const std::size_t current = displayWidth(text);
    if (current >= width) {
        return text;
    }
    return text + std::string(width - current, ' ');
}

std::string clipToDisplayWidth(const std::string& text, std::size_t width) {
    std::size_t columns = 0;
    std::size_t i = 0;
    while (i < text.size()) {
        const std::size_t length =
            utf8SequenceLength(static_cast<unsigned char>(text[i]));
        if (i + length > text.size()) {
            break;  // truncated trailing sequence: drop it
        }
        const std::uint32_t code = decodeCodepoint(text, i, length);
        std::size_t cell = 1;
        if (isZeroWidthCodepoint(code)) {
            cell = 0;
        } else if (isWideCodepoint(code)) {
            cell = 2;
        }
        if (columns + cell > width) {
            break;
        }
        columns += cell;
        i += length;
    }
    return text.substr(0, i);
}

}  // namespace sysinfo
