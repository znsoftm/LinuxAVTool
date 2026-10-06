// sysinfo - filesystem / disk usage information collection implementation

#include "sysinfo/disk_info.h"

#include <sys/statvfs.h>

#include <cstdint>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace sysinfo {

namespace {

const char* kMountsPath = "/proc/mounts";

// Filesystem types that do not represent real storage; they are skipped when
// enumerating disks so that virtual/pseudo filesystems are not aggregated.
bool isVirtualFsType(const std::string& fsType) {
    static const char* kVirtualTypes[] = {
        "proc",       "sysfs",     "devtmpfs",   "devpts",   "tmpfs",
        "cgroup",     "cgroup2",   "securityfs", "pstore",   "bpf",
        "autofs",     "hugetlbfs", "mqueue",     "debugfs",  "tracefs",
        "configfs",   "fusectl",   "efivarfs",   "ramfs",    "binfmt_misc",
        "rpc_pipefs", "nfsd",      "selinuxfs",  "systemd-1"};
    for (std::size_t i = 0; i < sizeof(kVirtualTypes) / sizeof(kVirtualTypes[0]);
         ++i) {
        if (fsType == kVirtualTypes[i]) {
            return true;
        }
    }
    return false;
}

// /proc/mounts escapes space, tab, newline and backslash as octal sequences
// (e.g. "\040"). Decode them so mount points can be passed to statvfs(3).
std::string unescapeMountField(const std::string& field) {
    std::string result;
    result.reserve(field.size());
    for (std::size_t i = 0; i < field.size(); ++i) {
        if (field[i] == '\\' && i + 3 < field.size() &&
            field[i + 1] >= '0' && field[i + 1] <= '7' &&
            field[i + 2] >= '0' && field[i + 2] <= '7' &&
            field[i + 3] >= '0' && field[i + 3] <= '7') {
            const unsigned int code =
                static_cast<unsigned int>(field[i + 1] - '0') * 64u +
                static_cast<unsigned int>(field[i + 2] - '0') * 8u +
                static_cast<unsigned int>(field[i + 3] - '0');
            result.push_back(static_cast<char>(code));
            i += 3;
        } else {
            result.push_back(field[i]);
        }
    }
    return result;
}

std::uint64_t multiply(std::uint64_t a, std::uint64_t b) {
    return a * b;
}

}  // namespace

double FilesystemInfo::usedPercent() const {
    if (totalBytes == 0) {
        return 0.0;
    }
    return static_cast<double>(usedBytes) * 100.0 /
           static_cast<double>(totalBytes);
}

double DiskInfo::usedPercent() const {
    if (totalBytes == 0) {
        return 0.0;
    }
    return static_cast<double>(usedBytes) * 100.0 /
           static_cast<double>(totalBytes);
}

FilesystemInfo collectFilesystemInfo(const std::string& mountPoint) {
    FilesystemInfo fs;
    fs.mountPoint = mountPoint;

    struct statvfs stats;
    if (statvfs(mountPoint.c_str(), &stats) != 0) {
        return fs;  // valid stays false
    }

    std::uint64_t blockSize = stats.f_frsize;
    if (blockSize == 0) {
        blockSize = stats.f_bsize;
    }

    fs.blockSize = blockSize;
    fs.totalBytes = multiply(static_cast<std::uint64_t>(stats.f_blocks), blockSize);
    fs.freeBytes = multiply(static_cast<std::uint64_t>(stats.f_bfree), blockSize);
    fs.availableBytes =
        multiply(static_cast<std::uint64_t>(stats.f_bavail), blockSize);
    if (fs.totalBytes >= fs.freeBytes) {
        fs.usedBytes = fs.totalBytes - fs.freeBytes;
    }

    fs.totalInodes = static_cast<std::uint64_t>(stats.f_files);
    fs.freeInodes = static_cast<std::uint64_t>(stats.f_ffree);

    fs.valid = true;
    return fs;
}

DiskInfo collectDiskInfo() {
    DiskInfo info;

    std::ifstream mounts(kMountsPath);
    if (!mounts.is_open()) {
        return info;  // valid stays false
    }

    std::set<std::string> seenDevices;
    std::string line;
    while (std::getline(mounts, line)) {
        std::istringstream fields(line);
        std::string device;
        std::string mountPoint;
        std::string fsType;
        if (!(fields >> device >> mountPoint >> fsType)) {
            continue;
        }

        device = unescapeMountField(device);
        mountPoint = unescapeMountField(mountPoint);

        if (isVirtualFsType(fsType)) {
            continue;
        }
        // Aggregate each backing device only once (bind mounts and the same
        // device mounted twice would otherwise inflate the totals).
        if (!seenDevices.insert(device).second) {
            continue;
        }

        FilesystemInfo fs = collectFilesystemInfo(mountPoint);
        if (!fs.valid) {
            continue;
        }
        // Mounts with no addressable blocks (e.g. nsfs) carry no usable
        // capacity information, so they are not reported as disks.
        if (fs.totalBytes == 0) {
            continue;
        }
        fs.device = device;
        fs.fsType = fsType;

        info.totalBytes += fs.totalBytes;
        info.usedBytes += fs.usedBytes;
        info.availableBytes += fs.availableBytes;
        info.filesystems.push_back(fs);
    }

    info.valid = !info.filesystems.empty();
    return info;
}

}  // namespace sysinfo
