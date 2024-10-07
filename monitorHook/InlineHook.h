#include "Common.h"

#include <android/log.h>
#include <string>

#ifndef MEMORY_INLINEHOOK_H
#define MEMORY_INLINEHOOK_H

#define INLINE_HOOK "InlineHook"
#define LOG_TAG "MonitorMemory"

#define LOGW(fmt, ...) ((void)__android_log_print(ANDROID_LOG_WARN, LOG_TAG, fmt,  ##__VA_ARGS__))
#define LOGE(fmt, ...) ((void)__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, fmt, ##__VA_ARGS__))

#define PROT_READ 0x1
#define PROT_WRITE 0x2
#define PROT_EXEC 0x4

class InlineHook {
public:
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

    static std::unordered_map<std::string, std::vector<ProcMap>> getAllMaps(int PID = -1);

    std::vector<Common::TrackHook> monitoringInlineHook();

private:
    std::unordered_map<std::string, std::vector<InlineHook::ProcMap>> previousMaps;
    std::unordered_map<std::string, std::vector<unsigned char>> hashLibs;

    void printLogChangeAccessRights(Common::SegmentAddress &previousSegment,
                                    Common::SegmentAddress &currentSegment,
                                    const std::string &change);

    void checkChangeAccessRights(InlineHook::ProcMap &previousProcMap,
                                 InlineHook::ProcMap &currentProcMap);

    void checkSegments(std::vector<InlineHook::ProcMap> &previousSegments,
                       std::vector<InlineHook::ProcMap> &currentSegments,
                       const std::string &pathname);

    std::vector<unsigned char> calculateHashFile(const std::string &filename);

    std::vector<unsigned char> calculateMemoryHash(Common::SegmentAddress &segmentAddress);

    unsigned char *calculateWindowHash(const char *buffer, size_t length);

    char *readWindowMemory(Common::SegmentAddress &segmentAddress, size_t &bytesRead);

    void checkWindowHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                         std::vector<Common::TrackHook> &hooks);

    void checkHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                   std::vector<Common::TrackHook> &hooks);

    bool matchesLib(const std::string &path);

    std::vector<Common::SegmentAddress> glueSegments(std::vector<InlineHook::ProcMap> &proces);
};


#endif
