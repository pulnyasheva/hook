#include "InlineHook.h"
#include "Common.h"

std::unordered_map<std::string, std::vector<Common::ProcMap>> InlineHook::previousMaps;
std::unordered_map<std::string, std::vector<unsigned char>> InlineHook::hashLibs;

void InlineHook::printLogChangeAccessRights(Common::SegmentAddress &previousSegment,
                                            Common::SegmentAddress &currentSegment,
                                            const std::string &change) {
    LOGW("Has changed access rights %s for memory segments: %llx-%llx",
         change.c_str(),
         std::max(previousSegment.startAddress, currentSegment.startAddress),
         std::min(previousSegment.endAddress, currentSegment.endAddress));
}

void InlineHook::checkChangeAccessRights(Common::ProcMap &previousProcMap,
                                         Common::ProcMap &currentProcMap) {
    if (previousProcMap.readable != currentProcMap.readable) {
        printLogChangeAccessRights(previousProcMap.address,
                                   currentProcMap.address, "readable");
    }

    if (previousProcMap.writeable != currentProcMap.writeable) {
        printLogChangeAccessRights(previousProcMap.address,
                                   currentProcMap.address, "writeable");
    }

    if (previousProcMap.executable != currentProcMap.executable) {
        printLogChangeAccessRights(previousProcMap.address,
                                   currentProcMap.address, "executable");
    }

    if (previousProcMap.is_private != currentProcMap.is_private) {
        printLogChangeAccessRights(previousProcMap.address,
                                   currentProcMap.address, "private");
    }

    if (previousProcMap.is_shared != currentProcMap.is_shared) {
        printLogChangeAccessRights(previousProcMap.address,
                                   currentProcMap.address, "shared");
    }
}

void InlineHook::checkSegments(std::vector<Common::ProcMap> &previousSegments,
                               std::vector<Common::ProcMap> &currentSegments,
                               const std::string &pathname) {
    std::sort(previousSegments.begin(), previousSegments.end());
    std::sort(currentSegments.begin(), currentSegments.end());

    if (currentSegments.size() > previousSegments.size()) {
        LOGW("There are more segments now for pathname: %s", pathname.c_str());

        if (previousSegments.empty())
            return;
    }

    if (currentSegments.size() < previousSegments.size()) {
        LOGW("There are fewer segments now for pathname: %s", pathname.c_str());

        if (currentSegments.empty())
            return;

    }

    unsigned int i = 0, j = 0;

    while (i < previousSegments.size() && j < currentSegments.size()) {
        unsigned long long startPrevious = previousSegments[i].address.startAddress,
                endPrevious = previousSegments[i].address.endAddress;
        unsigned long long startCurrent = currentSegments[j].address.startAddress,
                endCurrent = currentSegments[j].address.endAddress;

        if (startPrevious <= startCurrent <= endPrevious
            || startCurrent <= startPrevious <= endCurrent) {
            checkChangeAccessRights(previousSegments[i], currentSegments[j]);

            if (endPrevious == endCurrent) {
                i++;
                j++;
            } else if (endCurrent < endPrevious) {
                j++;
            } else {
                i++;
            }
        } else if (endCurrent <= startPrevious) {
            j++;
        } else if (endPrevious <= startCurrent) {
            i++;
        }
    }
}

unsigned char *InlineHook::calculateWindowHash(const char *buffer, size_t length) {
    unsigned char *hashOutput;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        LOGE("The EVP context could not be created.");
        return nullptr;
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        LOGE("Failed to initialize SHA256.");
        EVP_MD_CTX_free(mdctx);
        return nullptr;
    }

    if (EVP_DigestUpdate(mdctx, buffer, length) != 1) {
        LOGE("Error updating SHA256.");
    }

    hashOutput = new unsigned char[EVP_MD_size(md)];
    unsigned int hashLength;

    if (EVP_DigestFinal_ex(mdctx, hashOutput, &hashLength) != 1) {
        LOGE("Error when completing SHA256.");
        EVP_MD_CTX_free(mdctx);
        return nullptr;
    }

    EVP_MD_CTX_free(mdctx);

    return hashOutput;
}

char *InlineHook::readWindowMemory(Common::SegmentAddress &segmentAddress, size_t &bytesRead) {
    size_t size = segmentAddress.endAddress - segmentAddress.startAddress;
    char buffer[WINDOW_SIZE];
    size_t bytesToRead = std::min(WINDOW_SIZE, size - bytesRead);

    std::memcpy(buffer,
                reinterpret_cast<void *>(segmentAddress.startAddress + bytesRead),
                bytesToRead);

    bytesRead += bytesToRead;
    return buffer;
}

void
InlineHook::checkWindowHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                            std::vector<Common::TrackHook> &hooks) {
    size_t sizeSegment = segmentAddress.endAddress - segmentAddress.startAddress;
    size_t bytesReadMemory = 0;
    int countWindow = 0;
    char *bufferMemory;
    char bufferLib[WINDOW_SIZE];

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        LOGE("The file could not be opened");
        return;
    }

    while (bytesReadMemory < sizeSegment &&
           file.read(bufferLib, WINDOW_SIZE) || file.gcount() > 0) {
        bufferMemory = readWindowMemory(segmentAddress, bytesReadMemory);
        auto hashMemory = calculateWindowHash(bufferMemory, WINDOW_SIZE);
        auto hashLib = calculateWindowHash(bufferLib, WINDOW_SIZE);
        if (hashMemory != hashLib) {
            Common::TrackHook trackHook(std::make_unique<Common::InlineHook>(), INLINE_HOOK);
            auto *inlineHook = static_cast<Common::InlineHook *>(trackHook.hook.get());
            inlineHook->address.startAddress =
                    segmentAddress.startAddress + countWindow * WINDOW_SIZE;
            inlineHook->address.endAddress = std::min(
                    inlineHook->address.startAddress + WINDOW_SIZE,
                    segmentAddress.endAddress);
            hooks.push_back(std::move(trackHook));
        }
    }
}

void InlineHook::checkHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                           std::vector<Common::TrackHook> &hooks) {

    if (hashLibs.find(filename) == hashLibs.end()) {
        auto hashLib = Common::calculateHashFile(filename);
        hashLibs[filename] = hashLib;
    }

    auto hashMemory = Common::calculateMemoryHash(segmentAddress);
    auto hashLib = hashLibs[filename];
    if (hashMemory != hashLib) {
        checkWindowHash(segmentAddress, filename, hooks);
    }

}

bool matchesLib(const std::string &path) {
    std::regex pattern(R"(^([^/]+/)*[^/]+\.so$)");

    return std::regex_match(path, pattern);
}

std::vector<Common::TrackHook> InlineHook::monitoringInlineHook(int PID) {
    std::vector<Common::TrackHook> hooks;
    auto currentMaps = Common::getAllMaps(PID);

    if (!previousMaps.empty()) {
        for (auto &proc: currentMaps) {
            checkSegments(previousMaps[proc.first], proc.second, proc.first);
        }
    }

    for (auto &proc: currentMaps) {
        if (matchesLib(proc.first)) {
            std::vector<Common::SegmentAddress> gluedSegments = Common::glueSegments(proc.second);

            for (auto segment: gluedSegments) {
                checkHash(segment, proc.first, hooks);
            }
        }
    }

    previousMaps = currentMaps;
    return hooks;
}
