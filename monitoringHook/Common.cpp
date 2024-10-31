#include "Common.h"


namespace Common {
    std::unordered_map<std::string, std::vector<ProcMap>> getAllMaps(int PID) {
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

            resMaps[pathname].push_back(map);
        }

        fclose(fp);

        if (resMaps.empty()) {
            LOGE("getAllMaps err couldn't find any map");
        }

        return resMaps;
    }

    std::string getPathProcessFile(int PID) {
        std::string file = (PID == -1) ? "/proc/self/exe" :
                           "/proc/" + std::to_string(PID) + "/exe";
        char path[1024] = {0};
        ssize_t len = readlink(file.c_str(), path, sizeof(path));

        if (len == 0) {
            LOGE("Couldn't read link %s.", file.c_str());
            return "";
        }

        return path;
    }

    std::vector<unsigned char> calculateHashFile(const std::string &filename) {
        std::vector<unsigned char> hash(EVP_MAX_MD_SIZE);
        unsigned int hashLength;

        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (!mdctx) {
            LOGE("The EVP context could not be created.");
            return {};
        }

        if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
            LOGE("Failed to initialize SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        std::ifstream file(filename, std::ios::binary);
        if (!file) {
            LOGE("The file could not be opened.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        char buffer[WINDOW_SIZE];
        while (file.read(buffer, WINDOW_SIZE) || file.gcount() > 0) {
            if (EVP_DigestUpdate(mdctx, buffer, file.gcount()) != 1) {
                LOGE("Error updating SHA256.");
                EVP_MD_CTX_free(mdctx);
                return {};
            }
        }

        if (EVP_DigestFinal_ex(mdctx, hash.data(), &hashLength) != 1) {
            LOGE("Error when completing SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        hash.resize(hashLength);

        EVP_MD_CTX_free(mdctx);
        return hash;
    }

    std::vector<SegmentAddress>
    glueSegments(std::vector<ProcMap> &proces) {
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

    std::vector<unsigned char> finalizeHash(EVP_MD_CTX *mdctx, const char *buffer, size_t length) {
        if (EVP_DigestUpdate(mdctx, buffer, length) != 1) {
            LOGE("Error updating SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        std::vector<unsigned char> hashOutput(EVP_MD_size(EVP_sha256()));
        unsigned int hashLength;

        if (EVP_DigestFinal_ex(mdctx, hashOutput.data(), &hashLength) != 1) {
            LOGE("Error when completing SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        hashOutput.resize(hashLength);
        return hashOutput;
    }

    std::vector<unsigned char> calculateMemoryHash(SegmentAddress &segmentAddress) {
        size_t length = segmentAddress.endAddress - segmentAddress.startAddress;
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (!mdctx) {
            LOGE("The EVP context could not be created.");
            return {};
        }

        const EVP_MD *md = EVP_sha256();
        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
            LOGE("Failed to initialize SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        const char *buffer = reinterpret_cast<const char *>(segmentAddress.startAddress);

        auto hashOutput = finalizeHash(mdctx, buffer, length);

        EVP_MD_CTX_free(mdctx);
        return hashOutput;
    }

    std::vector<unsigned char> calculateMemoryHash(const std::vector<char> &data) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();

        if (!mdctx) {
            LOGE("The EVP context could not be created.");
            return {};
        }

        const EVP_MD *md = EVP_sha256();
        if (EVP_DigestInit_ex(mdctx, md, nullptr) != 1) {
            LOGE("Failed to initialize SHA256.");
            EVP_MD_CTX_free(mdctx);
            return {};
        }

        auto hashOutput = finalizeHash(mdctx, data.data(), data.size());

        EVP_MD_CTX_free(mdctx);
        return hashOutput;
    }
}
