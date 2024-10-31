#include "Tracker.h"
#include "Hook.h"
#include "Inline.h"
#include "Common.h"

#include <jni.h>
#include <string>

void tracking() {
    Tracker::Callback myCallback = [](const std::vector<Common::TrackHook>& hooks) {
        for (const auto& hook : hooks) {
            LOGE("Tracking hook %s", hook.typeHook.c_str());
        }
    };

    Tracker tracker(myCallback);

    tracker.start();
    std::this_thread::sleep_for(std::chrono::seconds(300));
    tracker.stop();
}

extern "C" {
JNIEXPORT jstring JNICALL
Java_com_example_monitoring_MainActivity_stringCos(JNIEnv *env, jobject obj, jint number) {
    std::string resultString = stringCos(number);
    return env->NewStringUTF(resultString.c_str());
}

void JNICALL
Java_com_example_monitoring_MainActivity_doInlineHook(JNIEnv *env, jobject obj) {
    doInlineHook();
}

void JNICALL
Java_com_example_monitoring_MainActivity_doInlineUnhook(JNIEnv *env, jobject obj) {
    doInlineUnhook();
}

void JNICALL
Java_com_example_monitoring_MainActivity_tracking(JNIEnv *env, jobject obj) {
    tracking();
}
}