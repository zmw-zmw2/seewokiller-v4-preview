#include "mcast_ctrl.h"

#include <map>
#include <set>

void McastController::setSigningKey(const uint8_t* priv, size_t len) {
    if (priv && len == SK_PRIV_LEN) {
        memcpy(m_priv, priv, SK_PRIV_LEN);
    }
}

void McastController::stop() {
    if (m_thread.joinable()) m_thread.join();
}

bool McastController::start(const std::string& bodyKv, int collectMs,
                            const std::vector<std::string>& targetIps,
                            ReplyCb onReply, DoneCb onDone) {
    if (m_busy.load()) return false;

    // Bind the dynamic reply port BEFORE sending so no reply is lost.
    SOCKET recvSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (recvSock == INVALID_SOCKET) return false;
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_ANY);
    a.sin_port = 0;
    if (bind(recvSock, (sockaddr*)&a, sizeof(a)) == SOCKET_ERROR) {
        closesocket(recvSock);
        return false;
    }
    int al = sizeof(a);
    getsockname(recvSock, (sockaddr*)&a, &al);
    unsigned replyPort = ntohs(a.sin_port);

    int64_t ts = 0;
    sk_cur_time_utc(&ts);
    uint32_t tid = sk_rand32();

    char json[SK_MAX_JSON];
    _snprintf(json, sizeof(json),
              "{\"task_id\":%u,\"ts\":%lld,\"reply_port\":%u,%s}",
              tid, (long long)ts, replyPort, bodyKv.c_str());
    json[sizeof(json) - 1] = '\0';
    if (strlen(json) > SK_MAX_JSON) { closesocket(recvSock); return false; }

    uint8_t pkt[SK_MAX_PACKET];
    size_t n = sk_build_packet(SK_MSG_COMMAND, json, m_priv, pkt, sizeof(pkt));
    if (n == 0) { closesocket(recvSock); return false; }

    SOCKET sendSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    int ttl = 4;
    setsockopt(sendSock, IPPROTO_IP, IP_MULTICAST_TTL, (const char*)&ttl, sizeof(ttl));
    sockaddr_in g{};
    g.sin_family = AF_INET;
    g.sin_addr.s_addr = inet_addr(SK_MCAST_GROUP);
    g.sin_port = htons(SK_MCAST_PORT);
    sendto(sendSock, (const char*)pkt, (int)n, 0, (sockaddr*)&g, sizeof(g));
    closesocket(sendSock);

    m_lastTask.store(tid);
    m_busy.store(true);
    if (m_thread.joinable()) m_thread.join();

    std::vector<uint8_t> pktVec(pkt, pkt + n);

    m_thread = std::thread([this, recvSock, collectMs, targetIps,
                            onReply, onDone, pktVec]() {
        const uint8_t* pkt = pktVec.data();
        const int pktLen = (int)pktVec.size();

        std::set<std::string> replied;               // ips with a final reply
        struct FragBuf { int total = 0; std::vector<std::string> parts; };
        std::map<std::string, FragBuf> frags;        // incomplete assemblies
        int total = 0;

        u_long nb = 1;
        ioctlsocket(recvSock, FIONBIO, &nb);

        // Receive until deadline; parse, reassemble fragments, emit replies.
        auto drain = [&](ULONGLONG deadline) {
            for (;;) {
                if (GetTickCount64() >= deadline) break;
                uint8_t buf[SK_MAX_PACKET];
                sockaddr_in from;
                int fl = sizeof(from);
                int r = recvfrom(recvSock, (char*)buf, sizeof(buf), 0,
                                 (sockaddr*)&from, &fl);
                if (r <= 0) { Sleep(25); continue; }

                uint8_t mt = 0;
                char js[SK_MAX_JSON + 1];
                // agent replies are unsigned (zero signature)
                if (sk_parse_packet(buf, (size_t)r, nullptr, &mt, js,
                                    sizeof(js)) != 0)
                    continue;
                if (mt != SK_MSG_REPLY) continue;

                std::string ip(inet_ntoa(from.sin_addr));
                McastReply base;
                base.ip = ip;
                char hb[128] = {0}, stb[32] = {0}, inb[600] = {0};
                if (sk_json_get_str(js, "host", hb, sizeof(hb)) == 0) base.host = hb;
                if (sk_json_get_str(js, "st", stb, sizeof(stb)) == 0) base.st = stb;
                if (sk_json_get_str(js, "info", inb, sizeof(inb)) == 0) base.info = inb;
                base.rc = sk_json_get_int(js, "rc", 0);
                base.task_id = sk_json_get_int(js, "task_id", 0);

                int ftotal = (int)sk_json_get_int(js, "ftotal", 1);
                int frag = (int)sk_json_get_int(js, "frag", 0);

                if (ftotal <= 1) {
                    if (!replied.insert(ip).second) continue;  // one per host
                    total++;
                    if (onReply) onReply(base);
                    continue;
                }
                if (ftotal > 16 || frag < 0 || frag >= ftotal) continue;

                FragBuf& fb = frags[ip];
                if (fb.total == 0) {
                    fb.total = ftotal;
                    fb.parts.resize((size_t)ftotal);
                }
                if (fb.total != ftotal || fb.parts[frag].empty()) {
                    if (fb.total == ftotal) fb.parts[frag] = base.info;
                    continue;
                }
                // duplicate fragment: ignore

                bool complete = true;
                for (const auto& p : fb.parts)
                    if (p.empty()) { complete = false; break; }
                if (!complete) continue;

                McastReply rep = base;
                rep.info.clear();
                for (const auto& p : fb.parts) rep.info += p;
                replied.insert(ip);
                total++;
                frags.erase(ip);
                if (onReply) onReply(rep);
            }
        };

        auto computeMissing = [&]() {
            std::vector<std::string> miss;
            for (const auto& ip : targetIps)
                if (!replied.count(ip)) miss.push_back(ip);
            return miss;
        };

        // Round 0: multicast window.
        drain(GetTickCount64() + (ULONGLONG)collectMs);
        std::vector<std::string> missing = computeMissing();

        // Reply-driven retransmit: unicast the SAME packet (same task_id,
        // agents dedup but re-reply) straight to silent targets.
        for (int round = 0; round < 2 && !missing.empty(); ++round) {
            SOCKET us = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (us != INVALID_SOCKET) {
                for (const auto& ip : missing) {
                    sockaddr_in t{};
                    t.sin_family = AF_INET;
                    t.sin_port = htons(SK_MCAST_PORT);
                    if (inet_pton(AF_INET, ip.c_str(), &t.sin_addr) == 1)
                        sendto(us, (const char*)pkt, pktLen, 0,
                               (sockaddr*)&t, sizeof(t));
                }
                closesocket(us);
            }
            drain(GetTickCount64() + 800);
            missing = computeMissing();
        }

        // Incomplete fragment assemblies: surface what arrived.
        for (auto& kv : frags) {
            if (replied.count(kv.first)) continue;
            int got = 0;
            for (const auto& p : kv.second.parts)
                if (!p.empty()) got++;
            McastReply rep;
            rep.ip = kv.first;
            rep.st = "part";
            rep.rc = -1;
            rep.info = "[\u7f3a\u5206\u7247 " + std::to_string(got) + "/" +
                       std::to_string(kv.second.total) + "] ";
            for (const auto& p : kv.second.parts) rep.info += p;
            replied.insert(kv.first);
            total++;
            if (onReply) onReply(rep);
        }

        closesocket(recvSock);
        m_busy.store(false);
        McastResult res;
        res.total = total;
        res.noReply = missing;
        if (onDone) onDone(res);
    });
    return true;
}
