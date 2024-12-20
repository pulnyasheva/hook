#include "Common.h"

#include <string>
#include <unistd.h>
#include <fstream>
#include <vector>
#include <elf.h>
#include <iostream>
#include <optional>

#ifndef MEMORY_GOTPLTHOOK_H
#define MEMORY_GOTPLTHOOK_H

#define GOTPLT_HOOK "GotPltHook"

class GotPltHook {
public:
    static std::vector<Common::TrackHook> monitoringGotPltHook(int PID = -1);

private:
    static bool initEntries;

    static int typeElf;

    static std::vector<unsigned char> hashFile;

    template<typename T>
    static std::unordered_map<std::string, std::vector<typename T::AddrType>> gotEntries;

    template<typename T>
    static bool isValidElfHeader(const typename T::Ehdr &header);

    static std::pair<std::vector<char>, unsigned long long>
    combineSegments(std::vector<Common::SegmentAddress> segmentAddresses);

    template<typename T>
    static std::unordered_map<std::string, std::vector<typename T::AddrType>>
    readElfFile(const char *filename);

    template<typename T>
    static std::unordered_map<std::string, std::pair<unsigned long long,
            std::vector<typename T::AddrType>>>
    readElfMemory(std::pair<std::vector<char>, unsigned long long> combinedSegments);

    template<typename T>
    static void compareGotEntries(
            const std::unordered_map<std::string, std::pair<unsigned long long,
                    std::vector<typename T::AddrType>>> &currentGotEntries,
            std::vector<Common::TrackHook> &hooks,
            const std::vector<Common::SegmentAddress> &segments);

    static int determineElfClass(const char *filename);

    static void initStandartElf(const char *file);

    static std::optional<unsigned long long>
    findSegment(const std::vector<Common::SegmentAddress> &segments,
                unsigned long long addressOffset);

    static std::vector<Common::SegmentAddress> findElf(int PID, std::string pathFile);

    struct Elf32 {
        using AddrType = Elf32_Addr;
        using Ehdr = Elf32_Ehdr;
        using Shdr = Elf32_Shdr;
    };

    struct Elf64 {
        using AddrType = Elf64_Addr;
        using Ehdr = Elf64_Ehdr;
        using Shdr = Elf64_Shdr;
    };
};

#endif
