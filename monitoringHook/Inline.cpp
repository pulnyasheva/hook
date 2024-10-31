#include <shadowhook.h>
#include "Hook.h"

#include <android/log.h>
#include <jni.h>

#define LOG_TAG "InlineHook"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

void *orig = NULL;
void *stub = NULL;

std::string proxy(int number) {
    double result = std::cos(number);
    char buffer[50];
    snprintf(buffer, sizeof(buffer), "Hooked cosine of %d is: %f", number, result);
    return std::string(buffer);
}

void doInlineHook() {
    LOGI("Hook");
    void *func_addr = (void *) stringCos;

    stub = shadowhook_hook_func_addr(func_addr,
                                     (void *) proxy,
                                     (void **) &orig);

    if (stub == nullptr) {
        int err_num = shadowhook_get_errno();
        const char *err_msg = shadowhook_to_errmsg(err_num);
        LOGI("Hook error %d - %s", err_num, err_msg);
    }
}

void doInlineUnhook() {
    LOGI("Unhook");
    shadowhook_unhook(stub);
    stub = nullptr;
}
