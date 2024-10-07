#include "InlineHook.h"
#include "Common.h"
#include <openssl/evp.h>
#include <iostream>
#include <fstream>
#include <cmath>

std::unordered_map<std::string, std::vector<InlineHook::ProcMap>> InlineHook::getAllMaps(int PID) {
    std::unordered_map<std::string, std::vector<ProcMap>> resMaps;
    std::string filePath = (PID == -1) ? "/proc/self/maps" : "/proc/" + std::to_string(PID) +
                                                             "/maps";
    char line[512] = {0};

    FILE *fp = fopen(filePath.c_str(), "r");
    if (!fp) {
        LOGE("Couldn't open file %s.", filePath.c_str());
        return resMaps;
    }

    while (fgets(line, sizeof(line), fp)) {
        ProcMap map;

        char perms[5] = {0}, dev[11] = {0}, pathname[256] = {0};
        // Парсинг строки из файла maps
        // Формат: startAddress-endAddress perms offset dev inode pathname
        if (sscanf(line, "%llx-%llx %s %llx %s %lu %s",
                   &map.address.startAddress, &map.address.endAddress,
                   perms, &map.offset, dev, &map.inode, pathname) < 6) {
            LOGW("Failed to parse line: %s", line);
            continue; // Если парсинг не удался, пропустить строку
        }

        map.length = map.address.endAddress - map.address.startAddress;
        map.dev = dev;
        map.pathname = pathname;

        if (perms[0] == 'r') {
            map.protection |= PROT_READ;
            map.readable = true;
        }
        if (perms[1] == 'w') {
            map.protection |= PROT_WRITE;
            map.writeable = true;
        }
        if (perms[2] == 'x') {
            map.protection |= PROT_EXEC;
            map.executable = true;
        }

        map.is_private = (perms[3] == 'p');
        map.is_shared = (perms[3] == 's');

        // Вставка в результирующую карту
        resMaps[pathname].push_back(map);
    }

    fclose(fp);

    if (resMaps.empty()) {
        LOGE("getAllMaps err couldn't find any map");
    }

    return resMaps;
}

void InlineHook::printLogChangeAccessRights(Common::SegmentAddress &previousSegment,
                                            Common::SegmentAddress &currentSegment,
                                            const std::string &change) {
    LOGW("Has changed access rights %s for memory segments: %llx-%llx",
         change.c_str(),
         std::max(previousSegment.startAddress, currentSegment.startAddress),
         std::min(previousSegment.endAddress, currentSegment.endAddress));
}

void InlineHook::checkChangeAccessRights(InlineHook::ProcMap &previousProcMap,
                                         InlineHook::ProcMap &currentProcMap) {
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

void InlineHook::checkSegments(std::vector<InlineHook::ProcMap> &previousSegments,
                               std::vector<InlineHook::ProcMap> &currentSegments,
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

std::vector<unsigned char> InlineHook::calculateHashFile(const std::string &filename) {
    std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
    unsigned int hashLength;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        std::cerr << "The EVP context could not be created." << std::endl;
        return {};
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
        std::cerr << "Failed to initialize SHA256." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        std::cerr << "The file could not be opened." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    char buffer[WINDOW_SIZE];
    while (file.read(buffer, WINDOW_SIZE) || file.gcount() > 0) {
        if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
            std::cerr << "Error updating SHA256." << std::endl;
            EVP_MD_CTX_free(mdctx);
            return {};
        }
    }

    if (EVP_DigestFinal_ex(mdctx, hash.data(), &hashLength) != 1) {
        std::cerr << "Error when completing SHA256." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    hash.resize(hashLength);

    EVP_MD_CTX_free(mdctx);
    return hash;
}

std::vector<unsigned char> InlineHook::calculateMemoryHash(Common::SegmentAddress &segmentAddress) {
    size_t length = segmentAddress.endAddress - segmentAddress.startAddress;
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

    if (!mdctx) {
        std::cerr << "The EVP context could not be created." << std::endl;
        return {};
    }

    const EVP_MD *md = EVP_sha256();
    if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
        std::cerr << "Failed to initialize SHA256." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    const char *buffer = reinterpret_cast<const char *>(segmentAddress.startAddress);

    if (EVP_DigestUpdate(mdctx, buffer, length) != 1) {
        std::cerr << "Error updating SHA256." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    std::vector<unsigned char> hashOutput(EVP_MD_size(md));
    unsigned int hashLength;

    if (EVP_DigestFinal_ex(mdctx, hashOutput.data(), &hashLength) != 1) {
        std::cerr << "Error when completing SHA256." << std::endl;
        EVP_MD_CTX_free(mdctx);
        return {};
    }

    EVP_MD_CTX_free(mdctx);
    hashOutput.resize(hashLength);
    return hashOutput;
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
            Common::TrackHook trackHook;
            trackHook.typeHook = INLINE_HOOK;
            Common::SegmentAddress &hookAddress = trackHook.address;
            hookAddress.startAddress = segmentAddress.startAddress + countWindow * WINDOW_SIZE;
            hookAddress.endAddress = std::min(hookAddress.startAddress + WINDOW_SIZE,
                                              segmentAddress.endAddress);
            hooks.push_back(trackHook);
        }
    }
}

void InlineHook::checkHash(Common::SegmentAddress &segmentAddress, const std::string &filename,
                           std::vector<Common::TrackHook> &hooks) {


    if (hashLibs.find(filename) == hashLibs.end()) {
        auto hashLib = calculateHashFile(filename);
        hashLibs[filename] = hashLib;
    }

    auto hashMemory = calculateMemoryHash(segmentAddress);
    auto hashLib = hashLibs[filename];
    if (hashMemory != hashLib) {
        checkWindowHash(segmentAddress, filename, hooks);
    }

}

std::vector<Common::SegmentAddress>
InlineHook::glueSegments(std::vector<InlineHook::ProcMap> &proces) {
    std::sort(proces.begin(), proces.end());
    std::vector<Common::SegmentAddress> addresses;
    addresses.push_back(proces[0].address);

    for (unsigned int i = 1; i < proces.size(); i++) {
        Common::SegmentAddress &previousSegment = addresses[addresses.size() - 1];
        Common::SegmentAddress &currentAddress = proces[i].address;

        if (previousSegment.endAddress >= currentAddress.startAddress) {
            previousSegment.endAddress =
                    std::max(previousSegment.endAddress, currentAddress.endAddress);
        }
    }

    return addresses;
}

bool InlineHook::matchesLib(const std::string &path) {
    std::regex pattern(R"(^([^/]+/)*[^/]+\.so$)");

    return std::regex_match(path, pattern);
}

std::vector<Common::TrackHook> InlineHook::monitoringInlineHook() {
    std::vector<Common::TrackHook> hooks;
    auto currentMaps = InlineHook::getAllMaps();

    if (!previousMaps.empty()) {
        for (auto &proc: currentMaps) {
            checkSegments(previousMaps[proc.first], proc.second, proc.first);
        }
    }

    for (auto &proc: previousMaps) {
        if (matchesLib(proc.first)) {
            std::vector<Common::SegmentAddress> gluedSegments = glueSegments(proc.second);
            for (auto segment: gluedSegments) {
                checkWindowHash(segment, proc.first, hooks);
            }
        }
    }

    previousMaps = currentMaps;
    return hooks;
}










