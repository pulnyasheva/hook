#include <string>
#include <utility>
#include <unistd.h>
#include <fstream>
#include <openssl/evp.h>
#include <android/log.h>

#ifndef MEMORY_COMMON_H
#define MEMORY_COMMON_H

#define LOG_TAG "MonitorMemory"

#define LOGW(fmt, ...) ((void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, fmt,  ##__VA_ARGS__))
#define LOGE(fmt, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__))

#define NOT_CLASS_ELF -1

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

const size_t WINDOW_SIZE = 4096;
const unsigned long long EMPTY_ADDRESS = static_cast<unsigned long long>(-1);

namespace Common {
    class SegmentAddress {
    public:
        unsigned long long startAddress;
        unsigned long long endAddress;

        explicit SegmentAddress() :
                startAddress(0), endAddress(0) {};

        bool operator<(const SegmentAddress &other) const {
            if (startAddress != other.startAddress) {
                return startAddress < other.startAddress;
            }
            return endAddress < other.endAddress;
        }
    };

    class ProcMap {
    public:
        Common::SegmentAddress address;
        size_t length;
        int protection;
        bool readable, writeable, executable, is_private, is_shared;
        unsigned long long offset;
        std::string dev;
        unsigned long inode;
        std::string pathname;

        ProcMap() : address(), length(0), protection(0),
                    readable(false), writeable(false), executable(false),
                    is_private(false), is_shared(false),
                    offset(0), inode(0) {}

        bool operator<(const ProcMap &other) const {
            return address < other.address;
        }
    };

    class Hook {
    public:
        virtual ~Hook() = default;
    };

    class InlineHook : public Hook {
    public:
        SegmentAddress address;
    };

    class GotPltHook : public Hook {
    public:
        unsigned long long startAddress;
        unsigned long long oldAddress;
        unsigned long long newAddress;
    };

    class TrackHook {
    public:
        std::unique_ptr<Hook> hook;
        std::string typeHook;

        TrackHook(std::unique_ptr<Hook> h, const std::string &type)
                : hook(std::move(h)), typeHook(type) {}
    };

    std::unordered_map<std::string, std::vector<ProcMap>> getAllMaps(int PID = -1);

    std::string getPathProcessFile(int PID = -1);

    std::vector<unsigned char> calculateHashFile(const std::string &filename);

    std::vector<SegmentAddress> glueSegments(std::vector<ProcMap> &proces);

    std::vector<unsigned char> calculateMemoryHash(SegmentAddress &segmentAddress);

    std::vector<unsigned char> calculateMemoryHash(const std::vector<char> &data);
}

#endif
