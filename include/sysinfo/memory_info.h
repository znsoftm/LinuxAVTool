// sysinfo - memory information collection
//
// Reads physical memory and swap statistics from /proc/meminfo on Linux.

#ifndef SYSINFO_MEMORY_INFO_H
#define SYSINFO_MEMORY_INFO_H

#include <cstdint>
#include <string>

namespace sysinfo {

// Physical memory and swap usage snapshot, all values in bytes.
struct MemoryInfo {
    bool valid = false;

    std::uint64_t totalBytes = 0;
    std::uint64_t freeBytes = 0;
    std::uint64_t availableBytes = 0;  // best estimate of memory usable by apps
    std::uint64_t buffersBytes = 0;
    std::uint64_t cachedBytes = 0;      // Cached + SReclaimable - Shmem
    std::uint64_t usedBytes = 0;        // total - available

    std::uint64_t swapTotalBytes = 0;
    std::uint64_t swapFreeBytes = 0;
    std::uint64_t swapUsedBytes = 0;

    std::string sourcePath;  // where the data came from, e.g. /proc/meminfo

    // Convenience accessors (0.0 when the corresponding total is unknown).
    double usedPercent() const;
    double swapUsedPercent() const;
};

// Collect memory statistics. Returns a MemoryInfo with valid == false when
// /proc/meminfo cannot be read.
MemoryInfo collectMemoryInfo();

}  // namespace sysinfo

#endif  // SYSINFO_MEMORY_INFO_H
