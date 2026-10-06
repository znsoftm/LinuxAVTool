// sysinfo - filesystem / disk usage information collection
//
// Uses statvfs(3) to query space usage and /proc/mounts to enumerate mounted
// filesystems on Linux.

#ifndef SYSINFO_DISK_INFO_H
#define SYSINFO_DISK_INFO_H

#include <cstdint>
#include <string>
#include <vector>

namespace sysinfo {

// Usage information for a single mounted filesystem, all sizes in bytes.
struct FilesystemInfo {
    bool valid = false;

    std::string device;      // backing device, e.g. /dev/nvme0n1p2
    std::string mountPoint;  // mount path, e.g. /
    std::string fsType;      // filesystem type, e.g. ext4

    std::uint64_t blockSize = 0;       // fragment size used for accounting
    std::uint64_t totalBytes = 0;      // total space
    std::uint64_t freeBytes = 0;       // free space (incl. reserved)
    std::uint64_t availableBytes = 0;  // free space available to unprivileged users
    std::uint64_t usedBytes = 0;       // total - free
    std::uint64_t totalInodes = 0;
    std::uint64_t freeInodes = 0;

    double usedPercent() const;
};

// Aggregate disk usage across all real mounted filesystems.
struct DiskInfo {
    bool valid = false;

    std::vector<FilesystemInfo> filesystems;
    std::uint64_t totalBytes = 0;
    std::uint64_t usedBytes = 0;
    std::uint64_t availableBytes = 0;

    double usedPercent() const;
};

// Query a single mount point with statvfs(3).
// Returns a FilesystemInfo with valid == false on failure.
FilesystemInfo collectFilesystemInfo(const std::string& mountPoint);

// Enumerate real (non-virtual) mounted filesystems from /proc/mounts and
// aggregate their usage. Returns a DiskInfo with valid == false when no
// filesystem could be inspected.
DiskInfo collectDiskInfo();

}  // namespace sysinfo

#endif  // SYSINFO_DISK_INFO_H
