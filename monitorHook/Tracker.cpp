#include "Tracker.h"
#include "Common.h"
#include "InlineHook.h"

Tracker::Tracker(Callback callback) : running(false), callback(callback) {}

Tracker::~Tracker() {
    stop();
}

void Tracker::start() {
    running = true;
    trackingThread = std::thread(&Tracker::tracking, this);
}

void Tracker::stop() {
    running = false;
    if (trackingThread.joinable()) {
        trackingThread.join();
    }
}

void Tracker::tracking() {
    while (running) {
        std::vector<Common::TrackHook> newHook = InlineHook::monitoringInlineHook();

        if (callback) {
            callback(newHook);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}
