#pragma once
// Console-side multicast controller: signs and sends one command packet to
// the agent multicast group, then collects small signed replies on a fresh
// random UDP port for a fixed window.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <functional>
#include <atomic>
#include <thread>
#include <cstdint>

struct McastReply {
    std::string ip;
    std::string host;
    std::string st;
    std::string info;
    long long rc = 0;
    long long task_id = 0;
};

class McastController {
public:
    using ReplyCb = std::function<void(const McastReply&)>;
    using DoneCb = std::function<void(int totalUnique)>;

    void setKey(const uint8_t key[32]);
    bool busy() const { return m_busy.load(); }
    uint32_t lastTaskId() const { return m_lastTask.load(); }

    // bodyKv: inner JSON members, e.g. "\"action\":\"exec\",\"cmd\":\"notepad.exe\"".
    // Returns false if busy or socket setup failed.
    bool start(const std::string& bodyKv, int collectMs,
               ReplyCb onReply, DoneCb onDone);

    // Wait for the collector thread (call on shutdown).
    void stop();

private:
    uint8_t m_key[32] = {0};
    std::atomic<bool> m_busy{false};
    std::atomic<uint32_t> m_lastTask{0};
    std::thread m_thread;
};
