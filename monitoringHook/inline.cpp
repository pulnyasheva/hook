#include <shadowhook.h>
#include "Hook.h"

#include <android/log.h>
#include <jni.h>


#define LOG_TAG "InlineHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void *orig = NULL;
void *stub = NULL;

jstring proxy(JNIEnv *env, jobject obj, jint number) {
    double result = std::cos(number);
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "Hooked cosine of %d is: %f", number, result);
    return env->NewStringUTF(buffer);
}

void doInlineHook() {
    LOGI("hook");
    void *func_addr = (void *) Java_com_example_memory_MainActivity_stringCos;

    stub = shadowhook_hook_func_addr(func_addr,
                                     (void *) proxy,
                                     (void **) &orig);

    if (stub == nullptr) {
        int err_num = shadowhook_get_errno();
        const char *err_msg = shadowhook_to_errmsg(err_num);
        LOGI("hook error %d - %s", err_num, err_msg);
    }
}

void doInlineUnhook() {
    LOGI("unhook");
    shadowhook_unhook(stub);
    stub = nullptr;
}

extern "C" {
JNIEXPORT void JNICALL
Java_com_example_memory_MainActivity_doInlineHook(JNIEnv *env, jobject obj) {
    doInlineHook();
}

JNIEXPORT void JNICALL
Java_com_example_memory_MainActivity_doInlineUnhook(JNIEnv *env, jobject obj) {
    doInlineUnhook();
}
}
