#ifndef MEMORY_HOOK_H
#define MEMORY_HOOK_H

#include <jni.h>
#include <cmath>

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jstring JNICALL
Java_com_example_memory_MainActivity_stringCos(JNIEnv *env, jobject obj, jint number) {
    double result = std::cos(number);
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "Original cosine of %d is: %f", number, result);
    return env->NewStringUTF(buffer);
}

#ifdef __cplusplus
}
#endif

#endif
