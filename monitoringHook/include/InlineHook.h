#include "Common.h"

#include <string>
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <cmath>
#include <regex>

#ifndef MEMORY_INLINEHOOK_H
#define MEMORY_INLINEHOOK_H

#define INLINE_HOOK "InlineHook"

class InlineHook {
public:
    static std::vector<Common::TrackHook> monitoringInlineHook(int PID = -1);

private:
    static std::unordered_map<std::string, std::vector<Common::ProcMap>> previousMaps;
    static std::unordered_map<std::string, std::vector<unsigned char>> hashLibs;

    static void printLogChangeAccessRights(Common::SegmentAddress &previousSegment,
                                           Common::SegmentAddress &currentSegment,
                                           const std::string &change);

    static void checkChangeAccessRights(Common::ProcMap &previousProcMap,
                                        Common::ProcMap &currentProcMap);

    static void checkSegments(std::vector<Common::ProcMap> &previousSegments,
                              std::vector<Common::ProcMap> &currentSegments,
                              const std::string &pathname);

    static unsigned char *calculateWindowHash(const char *buffer, size_t length);

    static char *readWindowMemory(Common::SegmentAddress &segmentAddress, size_t &bytesRead);

    static void checkWindowHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                                std::vector<Common::TrackHook> &hooks);

    static void checkHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                          std::vector<Common::TrackHook> &hooks);
};


#endif
