#include "Common.h"

#include <thread>
#include <chrono>

#ifndef MEMORY_TRACKER_H
#define MEMORY_TRACKER_H


class Tracker {
public:
    using Callback = std::function<void(const std::vector<Common::TrackHook>&)>;

    Tracker(Callback callback);
    ~Tracker();

    void start();
    void stop();

private:
    std::thread trackingThread;
    std::atomic<bool> running;
    Callback callback;

    void tracking(int PID = -1);
};


#endif
