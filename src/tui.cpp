// sysinfo - interactive terminal interface implementation
//
// A small full screen interface built directly on ANSI escape sequences and
// termios. It shows one tab per report section, animates information
// collection and ClamAV scans, and supports keyboard navigation.

#include "sysinfo/tui.h"

#include <poll.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "sysinfo/i18n.h"
#include "sysinfo/report.h"

namespace sysinfo {

namespace {

// ---- ANSI helpers ----------------------------------------------------------

const char* const kReset = "\033[0m";
const char* const kBold = "\033[1m";
const char* const kDim = "\033[2m";
const char* const kReverse = "\033[7m";
const char* const kCyan = "\033[36m";
const char* const kGreen = "\033[32m";
const char* const kYellow = "\033[33m";
const char* const kRed = "\033[31m";

std::string repeat(char c, int count) {
    return count > 0 ? std::string(static_cast<std::size_t>(count), c)
                     : std::string();
}

// Pad `text` with spaces to `width` display columns, clipping if needed.
std::string padLine(const std::string& text, int width) {
    if (width <= 0) {
        return std::string();
    }
    std::string out = clipToDisplayWidth(text, static_cast<std::size_t>(width));
    const std::size_t have = displayWidth(out);
    if (have < static_cast<std::size_t>(width)) {
        out += std::string(static_cast<std::size_t>(width) - have, ' ');
    }
    return out;
}

// Left aligned `left` and right aligned `right` on a `width` column line.
std::string twoColumn(const std::string& left, const std::string& right,
                      int width) {
    if (width <= 0) {
        return std::string();
    }
    const std::size_t lw = displayWidth(left);
    const std::size_t rw = displayWidth(right);
    if (lw + rw + 1 > static_cast<std::size_t>(width)) {
        return padLine(left, width);
    }
    return left + std::string(static_cast<std::size_t>(width) - lw - rw, ' ') +
           right;
}

// ---- Shared collection state ----------------------------------------------

// Data produced by the background collection / scan workers.
struct SharedState {
    static const int kTotalSteps = 3;

    std::mutex mutex;
    int completedSteps = 0;
    bool collectDone = false;

    MemoryInfo memory;
    DiskInfo disk;
    ScanEngine engine;

    bool scanActive = false;
    bool scanDone = false;
    ScanResult scanResult;
};

// ---- Terminal setup --------------------------------------------------------

volatile sig_atomic_t g_resized = 0;

// Restores the terminal on normal exit and on fatal signals.
struct TerminalGuard {
    bool active = false;
    struct termios saved;

    void restore() {
        if (!active) {
            return;
        }
        active = false;
        const char* seq = "\033[?25h\033[?1049l";
        ssize_t ignored = write(STDOUT_FILENO, seq, std::strlen(seq));
        (void)ignored;
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &saved);
    }
};

TerminalGuard* g_guard = NULL;

extern "C" void handleFatalSignal(int sig) {
    if (g_guard != NULL) {
        g_guard->restore();
    }
    _exit(128 + sig);
}

extern "C" void handleWinch(int) { g_resized = 1; }

// ---- Application -----------------------------------------------------------

class TuiApp {
  public:
    TuiApp(const LocaleInfo& locale, const TuiOptions& options,
           const Strings& strings)
        : locale_(locale), options_(options), s_(strings), shared_(new SharedState) {
        utf8_ = locale.utf8;
        if (utf8_) {
            spinner_ = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        } else {
            spinner_ = {"|", "/", "-", "\\"};
        }
        tabs_.push_back(s_.uiTabMemory);
        tabs_.push_back(s_.uiTabDisks);
        tabs_.push_back(s_.uiTabSecurity);
        tabs_.push_back(s_.uiTabLanguage);
    }

    int run() {
        querySize();
        startCollect();
        if (options_.scanRequested) {
            autoScanPending_ = true;
        }

        while (!quit_) {
            if (g_resized) {
                g_resized = 0;
                querySize();
            }
            maybeAutoScan();
            draw();
            waitForKey();
            ++tick_;
        }
        stopWorker();
        return exitCode();
    }

  private:
    // When the user passed --scan, run it as soon as collection finishes.
    void maybeAutoScan() {
        if (!autoScanPending_) {
            return;
        }
        bool done = false;
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            done = shared_->collectDone;
        }
        if (!done) {
            return;
        }
        autoScanPending_ = false;
        startScan();
    }
    // ---- data collection ---------------------------------------------------

    void startCollect() {
        stopWorker();
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            shared_->completedSteps = 0;
            shared_->collectDone = false;
            shared_->scanActive = false;
            shared_->scanDone = false;
            shared_->scanResult = ScanResult();
        }
        scanPerformed_ = false;
        phaseStart_ = std::chrono::steady_clock::now();

        std::shared_ptr<SharedState> state = shared_;
        worker_ = std::thread([state]() {
            MemoryInfo memory = collectMemoryInfo();
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->memory = memory;
                ++state->completedSteps;
            }
            DiskInfo disk = collectDiskInfo();
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->disk = disk;
                ++state->completedSteps;
            }
            ScanEngine engine = detectScanEngine();
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->engine = engine;
                ++state->completedSteps;
                state->collectDone = true;
            }
        });
    }

    void startScan() {
        bool ready = false;
        bool engineAvailable = false;
        ScanEngine engine;
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            ready = shared_->collectDone && !shared_->scanActive;
            engine = shared_->engine;
            engineAvailable = shared_->engine.available;
        }
        if (!ready) {
            return;
        }
        // With no explicit --scan target, scan the current working directory.
        const std::string target =
            options_.scanTarget.empty() ? std::string(".") : options_.scanTarget;
        if (!engineAvailable) {
            transient_ = s_.uiNoScanEngineHint;
            transientUntil_ = std::chrono::steady_clock::now() +
                              std::chrono::seconds(3);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            shared_->scanActive = true;
            shared_->scanDone = false;
        }
        scanPerformed_ = true;
        scanTarget_ = target;
        activeTab_ = 2;  // show the security tab while scanning
        phaseStart_ = std::chrono::steady_clock::now();

        std::shared_ptr<SharedState> state = shared_;
        const ScanOptions scanOptions = options_.scanOptions;
        stopWorker();
        worker_ = std::thread([state, engine, target, scanOptions]() {
            ScanResult result = scanPath(engine, target, scanOptions);
            {
                std::lock_guard<std::mutex> lock(state->mutex);
                state->scanResult = result;
                state->scanActive = false;
                state->scanDone = true;
            }
        });
    }

    void stopWorker() {
        if (worker_.joinable()) {
            // A running scan may outlive the interface; detaching keeps the
            // process exit prompt and the shared state stays alive via the
            // shared_ptr captured by the thread.
            worker_.detach();
        }
    }

    // ---- terminal ----------------------------------------------------------

    void querySize() {
        struct winsize ws;
        std::memset(&ws, 0, sizeof(ws));
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            width_ = ws.ws_col;
            height_ = ws.ws_row;
        } else {
            width_ = 80;
            height_ = 24;
        }
        if (width_ < 20) {
            width_ = 20;
        }
        if (height_ < 6) {
            height_ = 6;
        }
    }

    void writeAll(const std::string& text) {
        std::size_t written = 0;
        while (written < text.size()) {
            const ssize_t n =
                write(STDOUT_FILENO, text.data() + written, text.size() - written);
            if (n > 0) {
                written += static_cast<std::size_t>(n);
            } else if (n < 0 && errno == EINTR) {
                continue;
            } else {
                break;
            }
        }
    }

    int readByte(int timeoutMs) {
        struct pollfd pfd;
        pfd.fd = STDIN_FILENO;
        pfd.events = POLLIN;
        pfd.revents = 0;
        const int ready = poll(&pfd, 1, timeoutMs);
        if (ready > 0 && (pfd.revents & POLLIN)) {
            unsigned char c = 0;
            const ssize_t n = read(STDIN_FILENO, &c, 1);
            if (n == 1) {
                return static_cast<int>(c);
            }
        }
        return -1;
    }

    void waitForKey() {
        const int c = readByte(80);
        if (c < 0) {
            return;
        }
        if (c == 'q' || c == 'Q' || c == 3) {
            quit_ = true;
            return;
        }
        if (c == '\t') {
            nextTab(1);
            return;
        }
        if (c == 'j' || c == 'n') {
            scrollBy(1);
            return;
        }
        if (c == 'k' || c == 'p') {
            scrollBy(-1);
            return;
        }
        if (c == 'h') {
            nextTab(-1);
            return;
        }
        if (c == 'l') {
            nextTab(1);
            return;
        }
        if (c == 's' || c == 'S') {
            startScan();
            return;
        }
        if (c == 'r' || c == 'R') {
            startCollect();
            return;
        }
        if (c == 0x1b) {
            handleEscape();
            return;
        }
    }

    void handleEscape() {
        const int c2 = readByte(40);
        if (c2 != '[' && c2 != 'O') {
            return;  // bare ESC or unknown sequence
        }
        const int c3 = readByte(40);
        switch (c3) {
            case 'A':
                scrollBy(-1);
                break;
            case 'B':
                scrollBy(1);
                break;
            case 'C':
                nextTab(1);
                break;
            case 'D':
                nextTab(-1);
                break;
            case 'Z':
                nextTab(-1);
                break;
            default:
                break;
        }
    }

    void nextTab(int delta) {
        const int count = static_cast<int>(tabs_.size());
        activeTab_ = ((activeTab_ + delta) % count + count) % count;
    }

    void scrollBy(int delta) {
        const int maxTop = std::max(0, static_cast<int>(content_.size()) -
                                           contentHeight());
        scroll_[activeTab_] += delta;
        scroll_[activeTab_] = std::max(0, std::min(scroll_[activeTab_], maxTop));
    }

    int contentHeight() const { return std::max(1, height_ - 4); }

    // ---- rendering ---------------------------------------------------------

    void draw() {
        refreshContent();

        std::string out;
        out.reserve(static_cast<std::size_t>(width_) *
                        static_cast<std::size_t>(height_) +
                    256);
        out += "\033[H";

        out += std::string(kBold) +
               padLine(twoColumn(reportTitleLine(s_), reportGeneratedLine(s_),
                                 width_),
                       width_) +
               kReset;
        out += "\r\n";

        out += buildTabBar();
        out += "\r\n";

        const int rows = contentHeight();
        const int top = scroll_[activeTab_];
        for (int i = 0; i < rows; ++i) {
            const int index = top + i;
            if (index < static_cast<int>(content_.size())) {
                out += padLine(content_[static_cast<std::size_t>(index)], width_);
            } else {
                out += repeat(' ', width_);
            }
            out += "\r\n";
        }

        out += buildStatus();
        out += "\r\n";
        out += std::string(kDim) + padLine(s_.uiHint, width_) + kReset;

        writeAll(out);
    }

    std::string buildTabBar() const {
        std::string bar;
        std::size_t used = 0;
        for (std::size_t i = 0; i < tabs_.size(); ++i) {
            const std::string label = " " + tabs_[i] + " ";
            const std::size_t w = displayWidth(label);
            if (used + w > static_cast<std::size_t>(width_)) {
                break;
            }
            if (static_cast<int>(i) == activeTab_) {
                bar += std::string(kReverse) + kBold + label + kReset;
            } else {
                bar += label;
            }
            used += w;
        }
        if (used < static_cast<std::size_t>(width_)) {
            bar += repeat(' ', static_cast<int>(static_cast<std::size_t>(width_) - used));
        }
        return bar;
    }

    std::string buildStatus() const {
        const std::string spin = spinner_[static_cast<std::size_t>(tick_) %
                                          spinner_.size()];

        std::string plain;
        std::string colored;
        std::string color = kCyan;

        bool collecting = false;
        bool scanning = false;
        ScanEngine engine;
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            collecting = !shared_->collectDone;
            scanning = shared_->scanActive;
            engine = shared_->engine;
        }

        const double elapsed = elapsedSeconds();

        if (!transient_.empty() &&
            std::chrono::steady_clock::now() < transientUntil_) {
            plain = transient_;
            colored = std::string(kYellow) + transient_ + kReset;
        } else if (collecting) {
            int completed = 0;
            {
                std::lock_guard<std::mutex> lock(shared_->mutex);
                completed = shared_->completedSteps;
            }
            std::ostringstream text;
            text << s_.uiCollecting << "...  " << progressBar(18, completed / 3.0)
                 << "  " << formatElapsed(elapsed);
            plain = text.str();
            colored = std::string(kCyan) + spin + kReset + " " + text.str();
        } else if (scanning) {
            std::ostringstream text;
            text << s_.uiScanning << " " << scanTarget_ << "  "
                 << marquee(18) << "  " << formatElapsed(elapsed);
            plain = text.str();
            colored = std::string(kYellow) + spin + kReset + " " + text.str();
        } else {
            std::string state = s_.uiReady;
            bool infected = false;
            bool failed = false;
            {
                std::lock_guard<std::mutex> lock(shared_->mutex);
                if (shared_->scanDone) {
                    infected = shared_->scanResult.infected;
                    failed = !shared_->scanResult.valid;
                }
            }
            if (engine.available) {
                state += " - " + engine.name;
            }
            if (infected) {
                color = kRed;
                state = s_.msgScanInfected;
            } else if (failed) {
                color = kRed;
                state = s_.msgScanFailed;
            }
            plain = state;
            colored = std::string(color) + state + kReset;
        }

        const std::size_t have = displayWidth(plain);
        if (have < static_cast<std::size_t>(width_)) {
            colored += repeat(' ', static_cast<int>(static_cast<std::size_t>(width_) - have));
        }
        return colored;
    }

    double elapsedSeconds() const {
        const std::chrono::steady_clock::duration d =
            std::chrono::steady_clock::now() - phaseStart_;
        return std::chrono::duration_cast<std::chrono::milliseconds>(d).count() /
               1000.0;
    }

    std::string formatElapsed(double seconds) const {
        std::ostringstream out;
        out.precision(1);
        out << std::fixed << seconds << "s";
        return std::string(s_.uiElapsed) + " " + out.str();
    }

    std::string progressBar(int width, double fraction) const {
        if (fraction < 0.0) {
            fraction = 0.0;
        }
        if (fraction > 1.0) {
            fraction = 1.0;
        }
        const int filled = static_cast<int>(fraction * width + 0.5);
        std::string bar;
        for (int i = 0; i < width; ++i) {
            bar += i < filled ? '#' : '-';
        }
        return bar;
    }

    std::string marquee(int width) const {
        const int block = std::max(1, width / 5);
        const int span = std::max(1, width - block);
        const int cycle = span * 2;
        int pos = tick_ % cycle;
        if (pos > span) {
            pos = cycle - pos;
        }
        std::string bar;
        for (int i = 0; i < width; ++i) {
            bar += (i >= pos && i < pos + block) ? '=' : '-';
        }
        return bar;
    }

    void refreshContent() {
        content_.clear();

        bool collecting = false;
        bool scanning = false;
        MemoryInfo memory;
        DiskInfo disk;
        ScanEngine engine;
        bool scanDone = false;
        ScanResult scanResult;
        int completed = 0;
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            collecting = !shared_->collectDone;
            scanning = shared_->scanActive;
            memory = shared_->memory;
            disk = shared_->disk;
            engine = shared_->engine;
            scanDone = shared_->scanDone;
            scanResult = shared_->scanResult;
            completed = shared_->completedSteps;
        }

        if (collecting) {
            content_.push_back("");
            content_.push_back(std::string("  ") + spinner_[tick_ % spinner_.size()] +
                               "  " + s_.uiCollecting + "...");
            content_.push_back("");
            const char* labels[3] = {s_.sectionMemory, s_.sectionDisks,
                                     s_.sectionSecurity};
            for (int i = 0; i < 3; ++i) {
                const std::string mark = i < completed ? (utf8_ ? "✔" : "x") : " ";
                content_.push_back(std::string("    [") + mark + "] " + labels[i]);
            }
            return;
        }

        if (scanning && activeTab_ == 2) {
            content_.push_back("");
            content_.push_back(std::string("  ") + spinner_[tick_ % spinner_.size()] +
                               "  " + s_.uiScanning + " " + scanTarget_);
            content_.push_back("");
            content_.push_back(std::string("    ") + marquee(24));
            content_.push_back(std::string("    ") + formatElapsed(elapsedSeconds()));
            return;
        }

        switch (activeTab_) {
            case 0:
                content_ = memorySectionLines(memory, s_);
                break;
            case 1:
                content_ = diskSectionLines(disk, s_);
                break;
            case 2:
                content_ = securitySectionLines(engine, scanDone, scanResult,
                                                options_.scanOptions, s_);
                break;
            case 3:
            default:
                content_ = languageSectionLines(locale_, s_);
                break;
        }
    }

    // ---- exit code ---------------------------------------------------------

    int exitCode() const {
        ScanEngine engine;
        bool scanDone = false;
        ScanResult result;
        {
            std::lock_guard<std::mutex> lock(shared_->mutex);
            engine = shared_->engine;
            scanDone = shared_->scanDone;
            result = shared_->scanResult;
        }
        if (options_.scanRequested && !engine.available) {
            return 0;
        }
        if (scanPerformed_ && scanDone) {
            if (!result.valid) {
                return 2;
            }
            if (result.infected) {
                return 1;
            }
        }
        return 0;
    }

    // ---- members -----------------------------------------------------------

    LocaleInfo locale_;
    TuiOptions options_;
    const Strings& s_;

    std::shared_ptr<SharedState> shared_;
    std::thread worker_;

    std::vector<std::string> spinner_;
    std::vector<std::string> tabs_;
    std::vector<std::string> content_;

    bool utf8_ = false;
    bool scanPerformed_ = false;
    bool autoScanPending_ = false;
    bool quit_ = false;
    int activeTab_ = 0;
    int width_ = 80;
    int height_ = 24;
    int tick_ = 0;
    int scroll_[4] = {0, 0, 0, 0};

    std::string scanTarget_;
    std::string transient_;
    std::chrono::steady_clock::time_point transientUntil_;
    std::chrono::steady_clock::time_point phaseStart_;
};

}  // namespace

int runTui(const LocaleInfo& locale, const TuiOptions& options) {
    if (isatty(STDIN_FILENO) == 0 || isatty(STDOUT_FILENO) == 0) {
        return -1;  // caller falls back to the plain report
    }

    TerminalGuard guard;
    if (tcgetattr(STDIN_FILENO, &guard.saved) != 0) {
        return -1;
    }

    struct termios raw = guard.saved;
    raw.c_lflag &= static_cast<tcflag_t>(~(ICANON | ECHO | ISIG));
    raw.c_iflag &= static_cast<tcflag_t>(~(IXON | ICRNL));
    raw.c_oflag &= static_cast<tcflag_t>(~OPOST);
    raw.c_cc[VMIN] = 0;
    raw.c_cc[VTIME] = 0;
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &raw) != 0) {
        return -1;
    }

    guard.active = true;
    g_guard = &guard;

    struct sigaction sa;
    std::memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handleWinch;
    sigaction(SIGWINCH, &sa, NULL);

    struct sigaction fa;
    std::memset(&fa, 0, sizeof(fa));
    fa.sa_handler = handleFatalSignal;
    sigaction(SIGTERM, &fa, NULL);
    sigaction(SIGINT, &fa, NULL);
    sigaction(SIGHUP, &fa, NULL);

    const char* enter = "\033[?1049h\033[?25l\033[2J";
    ssize_t ignored = write(STDOUT_FILENO, enter, std::strlen(enter));
    (void)ignored;

    const Strings& strings = stringsFor(locale.uiLanguage);
    TuiApp app(locale, options, strings);
    const int code = app.run();

    guard.restore();
    g_guard = NULL;
    return code;
}

}  // namespace sysinfo
