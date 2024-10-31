#include "Common.h"
#include "GotPltHook.h"

bool GotPltHook::initEntries = false;
int GotPltHook::typeElf;
template<typename T>
std::unordered_map<std::string, std::vector<typename T::AddrType>> GotPltHook::gotEntries;
std::vector<unsigned char> GotPltHook::hashFile;

int GotPltHook::determineElfClass(const char *filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        LOGE("Cannot open file: %s", filename);
        return NOT_CLASS_ELF;
    }

    unsigned char ident[16];
    file.read(reinterpret_cast<char *>(ident), sizeof(ident));
    file.close();

    if (ident[EI_CLASS] == ELFCLASS32 || ident[EI_CLASS] == ELFCLASS64) {
        return ident[EI_CLASS];
    } else {
        LOGE("Unknown ELF class for file: %s", filename);
        return NOT_CLASS_ELF;
    }
}

template<typename T>
bool GotPltHook::isValidElfHeader(const typename T::Ehdr &header) {
    return (header.e_ident[EI_MAG0] == ELFMAG0 &&
            header.e_ident[EI_MAG1] == ELFMAG1 &&
            header.e_ident[EI_MAG2] == ELFMAG2 &&
            header.e_ident[EI_MAG3] == ELFMAG3);
}

template<typename T>
std::unordered_map<std::string, std::vector<typename T::AddrType>>
GotPltHook::readElfFile(const char *filename) {
    std::unordered_map<std::string, std::vector<typename T::AddrType>> currentGotEntries;
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        LOGE("Cannot open file: %s", filename);
        return currentGotEntries;
    }

    typename T::Ehdr header;
    file.read(reinterpret_cast<char *>(&header), sizeof(header));

    if (!isValidElfHeader<T>(header)) {
        LOGE("Not a valid ELF file: %s", filename);
        return currentGotEntries;
    }

    std::vector<typename T::Shdr> sectionHeaders(header.e_shnum);
    file.seekg(header.e_shoff);
    file.read(reinterpret_cast<char *>(sectionHeaders.data()),
              header.e_shnum * sizeof(typename T::Shdr));

    // Получаем имена секций
    typename T::Shdr strTab = sectionHeaders[header.e_shstrndx];
    std::vector<char> strTable(strTab.sh_size);
    file.seekg(strTab.sh_offset);
    file.read(strTable.data(), strTab.sh_size);

    int gotPltSection = 0;
    for (const auto &sec: sectionHeaders) {
        const char *sectionName = &strTable[sec.sh_name];
        if (strcmp(sectionName, ".got") == 0 || strcmp(sectionName, ".plt") == 0 ||
            strcmp(sectionName, ".got.plt") == 0 || strcmp(sectionName, ".plt.got") == 0) {

            gotPltSection++;

            std::vector<typename T::AddrType> entries(sec.sh_size / sizeof(typename T::AddrType));
            file.seekg(sec.sh_offset);
            file.read(reinterpret_cast<char *>(entries.data()), sec.sh_size);

            currentGotEntries[sectionName] = entries;

            if (gotPltSection == 4)
                break;
        }
    }

    file.close();

    return currentGotEntries;
}

std::pair<std::vector<char>, unsigned long long>
GotPltHook::combineSegments(std::vector<Common::SegmentAddress> segmentAddresses) {
    std::vector<char> combinedMemory;
    unsigned long long totalSize = 0;

    for (const auto &segment: segmentAddresses) {
        totalSize += (segment.endAddress - segment.startAddress);
        combinedMemory.resize(totalSize);
        std::memcpy(
                combinedMemory.data() + (totalSize - (segment.endAddress - segment.startAddress)),
                reinterpret_cast<void *>(segment.startAddress),
                segment.endAddress - segment.startAddress);
    }

    return std::make_pair(combinedMemory, totalSize);
}

template<typename T>
std::unordered_map<std::string, std::pair<unsigned long long, std::vector<typename T::AddrType>>>
GotPltHook::readElfMemory(std::pair<std::vector<char>, unsigned long long> combinedSegments) {
    std::unordered_map<std::string, std::pair<unsigned long long,
            std::vector<typename T::AddrType>>> currentGotEntries;

    if (combinedSegments.first.empty()) {
        LOGW("No memory for executable elf.");
        return currentGotEntries;
    }

    std::vector<char> combinedMemory = combinedSegments.first;
    unsigned long long totalSize = combinedSegments.second;

    typename T::Ehdr header;
    std::memcpy(&header, combinedMemory.data(), sizeof(header));

    if (!isValidElfHeader<T>(header)) {
        LOGE("Not a valid ELF file in memory.");
        return currentGotEntries;
    }

    if (totalSize < header.e_shoff + header.e_shnum * sizeof(typename T::Shdr)) {
        LOGE("Combined memory is too small to contain section headers.");
        return currentGotEntries;
    }

    std::vector<typename T::Shdr> sectionHeaders(header.e_shnum);
    std::memcpy(sectionHeaders.data(),
                combinedMemory.data() + header.e_shoff,
                header.e_shnum * sizeof(typename T::Shdr));

    typename T::Shdr strTab = sectionHeaders[header.e_shstrndx];

    if (totalSize < strTab.sh_offset + strTab.sh_size) {
        LOGE("Combined memory is too small to contain section string table.");
        return currentGotEntries;
    }

    std::vector<char> strTable(strTab.sh_size);
    std::memcpy(strTable.data(),
                combinedMemory.data() + strTab.sh_offset,
                strTab.sh_size);

    int gotPltSection = 0;
    for (const auto &sec: sectionHeaders) {
        const char *sectionName = &strTable[sec.sh_name];
        if (strcmp(sectionName, ".got") == 0 || strcmp(sectionName, ".plt") == 0 ||
            strcmp(sectionName, ".got.plt") == 0 || strcmp(sectionName, ".plt.got") == 0) {

            gotPltSection++;

            if (totalSize < sec.sh_offset + sec.sh_size) {
                LOGE("Combined memory is too small to contain section data for %s.", sectionName);
                break;
            }

            std::vector<typename T::AddrType> entries(sec.sh_size / sizeof(typename T::AddrType));
            std::memcpy(entries.data(),
                        combinedMemory.data() + sec.sh_offset,
                        sec.sh_size);

            currentGotEntries[sectionName] = std::make_pair(sec.sh_offset, entries);

            if (gotPltSection == 4)
                break;
        }
    }

    return currentGotEntries;
}

template<typename T>
void GotPltHook::compareGotEntries(
        const std::unordered_map<std::string, std::pair<unsigned long long,
                std::vector<typename T::AddrType>>> &currentGotEntries,
        std::vector<Common::TrackHook> &hooks,
        const std::vector<Common::SegmentAddress> &segments) {
    for (const auto &entry: gotEntries<T>) {
        const std::string &sectionName = entry.first;
        const auto &addrs = entry.second;

        if (currentGotEntries.find(sectionName) != currentGotEntries.end()) {
            const auto &pair = currentGotEntries.at(sectionName);
            const auto &newAddrs = pair.second;
            size_t minSize = std::min(addrs.size(), newAddrs.size());

            for (size_t i = 0; i < minSize; ++i) {
                if (addrs[i] != newAddrs[i]) {
                    Common::TrackHook trackHook(std::make_unique<Common::GotPltHook>(),
                                                GOTPLT_HOOK);
                    auto *gotPltHook = static_cast<Common::GotPltHook *>(trackHook.hook.get());
                    auto address = findSegment(segments, pair.first + (i * sizeof(typename T::AddrType)));
                    if (!address.has_value()) {
                        LOGE("The required address was not found");
                        continue;
                    }
                    gotPltHook->startAddress = *address;
                    gotPltHook->oldAddress = addrs[i];
                    gotPltHook->newAddress = newAddrs[i];
                    hooks.push_back(std::move(trackHook));
                }
            }

            if (newAddrs.size() > minSize) {
                for (size_t i = minSize; i < newAddrs.size(); ++i) {
                    Common::TrackHook trackHook(std::make_unique<Common::GotPltHook>(),
                                                GOTPLT_HOOK);
                    auto *gotPltHook = static_cast<Common::GotPltHook *>(trackHook.hook.get());
                    auto address = findSegment(segments, pair.first + (i * sizeof(typename T::AddrType)));
                    if (!address.has_value()) {
                        LOGE("The required address was not found");
                        continue;
                    }
                    gotPltHook->startAddress = *address;
                    gotPltHook->oldAddress = EMPTY_ADDRESS;
                    gotPltHook->newAddress = newAddrs[i];
                    hooks.push_back(std::move(trackHook));
                }
            }

            if (addrs.size() > minSize) {
                for (size_t i = minSize; i < addrs.size(); ++i) {
                    Common::TrackHook trackHook(std::make_unique<Common::GotPltHook>(),
                                                GOTPLT_HOOK);
                    auto *gotPltHook = static_cast<Common::GotPltHook *>(trackHook.hook.get());
                    auto address = findSegment(segments, pair.first + (i * sizeof(typename T::AddrType)));
                    if (!address.has_value()) {
                        LOGE("The required address was not found");
                        continue;
                    }
                    gotPltHook->startAddress = *address;
                    gotPltHook->oldAddress = addrs[i];
                    gotPltHook->newAddress = EMPTY_ADDRESS;
                    hooks.push_back(std::move(trackHook));
                }
            }
        }
    }
}

std::optional<unsigned long long>
GotPltHook::findSegment(const std::vector<Common::SegmentAddress> &segments,
                        unsigned long long addressOffset) {
    if (segments.empty()) {
        LOGE("Segments memory executable elf empty");
    }

    size_t index = 0;
    while (index < segments.size()) {
        unsigned long long address = segments[index].startAddress + addressOffset;

        if (address >= segments[index].startAddress && address < segments[index].endAddress) {
            return address;
        } else {
            addressOffset -= segments[index].endAddress - segments[index].startAddress;
        }
        index++;
    }

    return std::nullopt;
}

void GotPltHook::initStandartElf(const char *pathFile) {
    typeElf = determineElfClass(pathFile);

    if (typeElf == NOT_CLASS_ELF)
        return;

    if (typeElf == ELFCLASS32) {
        gotEntries<Elf32> = readElfFile<Elf32>(pathFile);
    }

    if (typeElf == ELFCLASS64) {
        gotEntries<Elf64> = readElfFile<Elf64>(pathFile);
    }

    initEntries = true;
    hashFile = Common::calculateHashFile(pathFile);
}

std::vector<Common::SegmentAddress> GotPltHook::findElf(int PID, std::string pathFile) {
    auto process = Common::getAllMaps(PID);
    std::vector<Common::SegmentAddress> segmentAddresses;

    for (auto &pair: process) {
        const std::string &key = pair.first;
        if (key == pathFile) {
            return Common::glueSegments(pair.second);
        }
    }

    return segmentAddresses;
}

std::vector<Common::TrackHook> GotPltHook::monitoringGotPltHook(int PID) {
    std::vector<Common::TrackHook> hooks;

    std::string pathExeFile = Common::getPathProcessFile(PID);

    if (typeElf == NOT_CLASS_ELF)
        return hooks;

    if (!initEntries) {
        initStandartElf(pathExeFile.c_str());
    }

    std::vector<Common::SegmentAddress> segmentAddressesFile = findElf(PID, pathExeFile);
    auto combinedSegmentsFile = combineSegments(segmentAddressesFile);

    if (typeElf == ELFCLASS32) {
        std::unordered_map<std::string, std::pair<unsigned long long,
                std::vector<Elf32::AddrType>>> currentGotEntries;
        if (Common::calculateMemoryHash(combinedSegmentsFile.first) != hashFile) {
            currentGotEntries = readElfMemory<Elf32>(combinedSegmentsFile);
            compareGotEntries<Elf32>(currentGotEntries, hooks, segmentAddressesFile);
        }
    }

    if (typeElf == ELFCLASS64) {
        std::unordered_map<std::string, std::pair<unsigned long long,
                std::vector<Elf64::AddrType>>> currentGotEntries;
        if (Common::calculateMemoryHash(combinedSegmentsFile.first) != hashFile) {
            currentGotEntries = readElfMemory<Elf64>(combinedSegmentsFile);
            compareGotEntries<Elf64>(currentGotEntries, hooks, segmentAddressesFile);
        }
    }

    return hooks;
}
