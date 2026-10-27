#pragma once
// Console-side multicast controller: signs and sends one command packet to
// the agent multicast group, then collects replies on a fresh random UDP
// port for a fixed window. Long replies arrive as frag/ftotal fragments and
// are reassembled here. Targets that never reply get the same packet
// re-sent by unicast (same task_id; agents dedup and re-reply), then are
// reported as offline.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <thread>
#include <cstdint>

#include "sk_protocol.h"

struct McastReply {
    std::string ip;
    std::string host;
    std::string st;
    std::string info;
    long long rc = 0;
    long long task_id = 0;
};

struct McastResult {
    int total = 0;                        // hosts that replied
    std::vector<std::string> noReply;     // target IPs that never replied
};

class McastController {
public:
    using ReplyCb = std::function<void(const McastReply&)>;
    using DoneCb = std::function<void(const McastResult&)>;

    void setSigningKey(const uint8_t* priv, size_t len);
    bool busy() const { return m_busy.load(); }
    uint32_t lastTaskId() const { return m_lastTask.load(); }

    // bodyKv: inner JSON members, e.g. "\"action\":\"exec\",\"cmd\":\"notepad.exe\"".
    // targetIps: resolved target list used to drive unicast re-sends.
    // Returns false if busy, key missing, or socket setup failed.
    bool start(const std::string& bodyKv, int collectMs,
               const std::vector<std::string>& targetIps,
               ReplyCb onReply, DoneCb onDone);

    // Wait for the collector thread (call on shutdown).
    void stop();

private:
    uint8_t m_priv[SK_PRIV_LEN] = {0};
    std::atomic<bool> m_busy{false};
    std::atomic<uint32_t> m_lastTask{0};
    std::thread m_thread;
};
