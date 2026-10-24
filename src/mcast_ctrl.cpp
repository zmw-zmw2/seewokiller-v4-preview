#include "mcast_ctrl.h"
#include "sk_protocol.h"

#include <set>

void McastController::setKey(const uint8_t key[32]) {
    memcpy(m_key, key, 32);
}

void McastController::stop() {
    if (m_thread.joinable()) m_thread.join();
}

bool McastController::start(const std::string& bodyKv, int collectMs,
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
    size_t n = sk_build_packet(SK_MSG_COMMAND, json, m_key, pkt, sizeof(pkt));
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

    m_thread = std::thread([this, recvSock, collectMs, onReply, onDone]() {
        std::set<std::string> seen;
        int total = 0;
        u_long nb = 1;
        ioctlsocket(recvSock, FIONBIO, &nb);
        ULONGLONG deadline = GetTickCount64() + (ULONGLONG)collectMs;

        for (;;) {
            if (GetTickCount64() >= deadline) break;
            uint8_t buf[SK_MAX_PACKET];
            sockaddr_in from;
            int fl = sizeof(from);
            int r = recvfrom(recvSock, (char*)buf, sizeof(buf), 0,
                             (sockaddr*)&from, &fl);
            if (r <= 0) { Sleep(25); continue; }

            uint8_t mt = 0;
            char json2[SK_MAX_JSON + 1];
            if (sk_parse_packet(buf, (size_t)r, m_key, &mt, json2, sizeof(json2)) != 0)
                continue;
            if (mt != SK_MSG_REPLY) continue;

            std::string ip(inet_ntoa(from.sin_addr));
            if (!seen.insert(ip).second) continue;   // one reply per host

            McastReply rep;
            rep.ip = ip;
            char hb[128] = {0}, stb[32] = {0}, inb[600] = {0};
            if (sk_json_get_str(json2, "host", hb, sizeof(hb)) == 0) rep.host = hb;
            if (sk_json_get_str(json2, "st", stb, sizeof(stb)) == 0) rep.st = stb;
            if (sk_json_get_str(json2, "info", inb, sizeof(inb)) == 0) rep.info = inb;
            rep.rc = sk_json_get_int(json2, "rc", 0);
            rep.task_id = sk_json_get_int(json2, "task_id", 0);

            total++;
            if (onReply) onReply(rep);
        }
        closesocket(recvSock);
        m_busy.store(false);
        if (onDone) onDone(total);
    });
    return true;
}
