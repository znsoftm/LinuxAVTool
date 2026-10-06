// sysinfo - memory information collection implementation

#include "sysinfo/memory_info.h"

#include <cstdint>
#include <fstream>
#include <map>
#include <sstream>
#include <string>

namespace sysinfo {

namespace {

const char* kMeminfoPath = "/proc/meminfo";

// Parse a single /proc/meminfo line such as:
//   MemTotal:       127600748 kB
// Stores the value converted to bytes in `out`. Returns false when the line
// does not carry a numeric value.
bool parseMeminfoLine(const std::string& line,
                      std::string& key,
                      std::uint64_t& out) {
    const std::string::size_type colon = line.find(':');
    if (colon == std::string::npos) {
        return false;
    }

    key = line.substr(0, colon);
    // Trim trailing whitespace from the key.
    while (!key.empty() &&
           (key[key.size() - 1] == ' ' || key[key.size() - 1] == '\t')) {
        key.erase(key.size() - 1);
    }

    std::istringstream rest(line.substr(colon + 1));
    unsigned long long value = 0;
    if (!(rest >> value)) {
        return false;
    }

    std::string unit;
    rest >> unit;

    std::uint64_t multiplier = 1;
    if (unit == "kB" || unit == "KB") {
        multiplier = 1024;
    } else if (unit == "MB") {
        multiplier = 1024ULL * 1024ULL;
    } else if (unit == "GB") {
        multiplier = 1024ULL * 1024ULL * 1024ULL;
    }
    // No unit (e.g. HugePages_Total) is treated as a plain count.

    out = static_cast<std::uint64_t>(value) * multiplier;
    return true;
}

std::uint64_t lookup(const std::map<std::string, std::uint64_t>& values,
                     const std::string& key) {
    const std::map<std::string, std::uint64_t>::const_iterator it =
        values.find(key);
    return it == values.end() ? 0 : it->second;
}

}  // namespace

double MemoryInfo::usedPercent() const {
    if (totalBytes == 0) {
        return 0.0;
    }
    return static_cast<double>(usedBytes) * 100.0 /
           static_cast<double>(totalBytes);
}

double MemoryInfo::swapUsedPercent() const {
    if (swapTotalBytes == 0) {
        return 0.0;
    }
    return static_cast<double>(swapUsedBytes) * 100.0 /
           static_cast<double>(swapTotalBytes);
}

MemoryInfo collectMemoryInfo() {
    MemoryInfo info;
    info.sourcePath = kMeminfoPath;

    std::ifstream file(kMeminfoPath);
    if (!file.is_open()) {
        return info;  // valid stays false
    }

    std::map<std::string, std::uint64_t> values;
    std::string line;
    while (std::getline(file, line)) {
        std::string key;
        std::uint64_t value = 0;
        if (parseMeminfoLine(line, key, value)) {
            values[key] = value;
        }
    }

    info.totalBytes = lookup(values, "MemTotal");
    info.freeBytes = lookup(values, "MemFree");
    info.buffersBytes = lookup(values, "Buffers");

    const std::uint64_t cached = lookup(values, "Cached");
    const std::uint64_t sreclaimable = lookup(values, "SReclaimable");
    const std::uint64_t shmem = lookup(values, "Shmem");
    // Match the traditional `free` accounting: reclaimable slab counts as
    // cache, shared memory is subtracted because it is also reported in Cached.
    if (cached + sreclaimable >= shmem) {
        info.cachedBytes = cached + sreclaimable - shmem;
    } else {
        info.cachedBytes = cached;
    }

    info.availableBytes = lookup(values, "MemAvailable");
    if (info.availableBytes == 0) {
        // Older kernels (< 3.14) do not expose MemAvailable.
        info.availableBytes =
            info.freeBytes + info.buffersBytes + info.cachedBytes;
    }
    if (info.availableBytes > info.totalBytes) {
        info.availableBytes = info.totalBytes;
    }

    if (info.totalBytes >= info.availableBytes) {
        info.usedBytes = info.totalBytes - info.availableBytes;
    }

    info.swapTotalBytes = lookup(values, "SwapTotal");
    info.swapFreeBytes = lookup(values, "SwapFree");
    if (info.swapTotalBytes >= info.swapFreeBytes) {
        info.swapUsedBytes = info.swapTotalBytes - info.swapFreeBytes;
    }

    info.valid = info.totalBytes != 0;
    return info;
}

}  // namespace sysinfo
