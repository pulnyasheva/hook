#include <string>

#ifndef MEMORY_COMMON_H
#define MEMORY_COMMON_H

const size_t WINDOW_SIZE = 4096;

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

    class TrackHook {
    public:
        SegmentAddress address;
        std::string typeHook;
    };
}

#endif
