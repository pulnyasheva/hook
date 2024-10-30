#include "Tracker.h"
#include "Common.h"
#include "InlineHook.h"
#include "GotPltHook.h"

Tracker::Tracker(Callback callback) : running(false), callback(callback) {
}

Tracker::~Tracker() {
    stop();
}

void Tracker::start() {
    running = true;
    trackingThread = std::thread([this]() {
        tracking();
    });
}

void Tracker::stop() {
    running = false;
    if (trackingThread.joinable()) {
        trackingThread.join();
    }
}

void Tracker::tracking(int PID) {
    while (running) {
        std::vector<Common::TrackHook> newInlineHook = InlineHook::monitoringInlineHook(PID);
        std::vector<Common::TrackHook> newGotPltHook = GotPltHook::monitoringGotPltHook(PID);

        std::vector<Common::TrackHook> combinedHooks;

        combinedHooks.reserve(newInlineHook.size() + newGotPltHook.size());
        combinedHooks.insert(combinedHooks.end(),
                             std::make_move_iterator(newInlineHook.begin()),
                             std::make_move_iterator(newInlineHook.end()));

        combinedHooks.insert(combinedHooks.end(),
                             std::make_move_iterator(newGotPltHook.begin()),
                             std::make_move_iterator(newGotPltHook.end()));

        if (callback) {
            callback(combinedHooks);
        }

        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
}
