#ifndef MEMORY_HOOK_H
#define MEMORY_HOOK_H

#include <jni.h>
#include <cmath>

inline std::string stringCos(int number) {
    double result = std::cos(number);
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "Original cosine of %d is: %f", number, result);
    return std::string(buffer);
}

#endif
