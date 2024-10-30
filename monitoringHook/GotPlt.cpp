#include "bytehook.h"
#include "Hook.h"

#include <android/log.h>
#include <jni.h>


#define LOG_TAG "GotPltHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void *orig = NULL;
void *stub = NULL;

double proxyCos(double number) {
    return number;
}

void doGotPltHook() {
    LOGI("Hook");

    stub = bytehook_hook_all(
            "libm.so",
            "cos",
            (void *) proxyCos,
            nullptr,
            nullptr);

    if (stub == NULL) {
        LOGI("Hook error");
    }
}

void doGotPltUnhook() {
    LOGI("Unhook");
    bytehook_unhook(stub);
    stub = NULL;
}

extern "C" {
void JNICALL
Java_com_example_memory_MainActivity_doGotPltHook(JNIEnv *env, jobject obj) {
    doGotPltHook();
}
void JNICALL
Java_com_example_memory_MainActivity_doGotPltUnhook(JNIEnv *env, jobject obj) {
    doGotPltUnhook();
}
}

