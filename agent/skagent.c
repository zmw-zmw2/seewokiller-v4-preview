// skagent.c - SeewoKiller resident agent (pure C / Win32, no deps).
// Deployed to C:\Temp\SK\ via SFTP and registered as an ONLOGON scheduled
// task (/RL HIGHEST) so it runs in the interactive desktop session.
// Listens on multicast SK_MCAST_GROUP:SK_MCAST_PORT, verifies signed
// commands, executes them in the desktop session, replies with a small
// unicast packet to the controller-chosen dynamic port.

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sk_protocol.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

#define AGENT_DIR      "C:\\Temp\\SK"
#define KEY_FILE       "C:\\Temp\\SK\\key.bin"
#define EDGE_PATH      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"

static uint8_t  g_key[SK_HMAC_LEN];
static char     g_host[64] = "?";
static SOCKET   g_replySock = INVALID_SOCKET;

/* ---------------- small helpers ---------------- */

static void run_hidden(const char* cmdline) {
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    char buf[1024];
    _snprintf(buf, sizeof(buf), "cmd.exe /c %s", cmdline);
    buf[sizeof(buf) - 1] = '\0';
    CreateProcessA(NULL, buf, NULL, NULL, FALSE,
                   CREATE_NO_WINDOW, NULL, AGENT_DIR, &si, &pi);
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread) CloseHandle(pi.hThread);
}

/* Run a command, wait up to waitMs, capture merged output (capped). */
static int run_capture(const char* cmd, DWORD waitMs, char* out, size_t outCap,
                       size_t* outLen) {
    SECURITY_ATTRIBUTES sa; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    HANDLE rd = NULL, wr = NULL;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return -1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = wr; si.hStdError = wr;
    ZeroMemory(&pi, sizeof(pi));

    char buf[1200];
    _snprintf(buf, sizeof(buf), "cmd.exe /c %s", cmd);
    buf[sizeof(buf) - 1] = '\0';

    BOOL ok = CreateProcessA(NULL, buf, NULL, NULL, TRUE, CREATE_NO_WINDOW,
                             NULL, AGENT_DIR, &si, &pi);
    CloseHandle(wr);
    if (!ok) { CloseHandle(rd); return -1; }

    size_t n = 0;
    char tmp[2048]; DWORD got = 0;
    ULONGLONG start = GetTickCount64();
    for (;;) {
        DWORD avail = 0;
        if (!PeekNamedPipe(rd, NULL, 0, NULL, &avail, NULL) || avail == 0) {
            if (WaitForSingleObject(pi.hProcess, 150) != WAIT_TIMEOUT) break;
            if (GetTickCount64() - start > waitMs) {
                TerminateProcess(pi.hProcess, 1);
                break;
            }
            continue;
        }
        DWORD want = avail < sizeof(tmp) ? avail : (DWORD)sizeof(tmp);
        if (!ReadFile(rd, tmp, want, &got, NULL) || got == 0) break;
        size_t room = outCap - n;
        size_t cp = got < room ? got : room;
        memcpy(out + n, tmp, cp);
        n += cp;
        if (n >= outCap) break;
    }
    while (n < outCap &&
           ReadFile(rd, tmp, (DWORD)sizeof(tmp), &got, NULL) && got > 0) {
        size_t room = outCap - n;
        size_t cp = got < room ? got : room;
        memcpy(out + n, tmp, cp);
        n += cp;
    }
    DWORD rc = 0;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(rd); CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    *outLen = n;
    return (int)rc;
}

/* ---------------- encoding helpers (protocol is UTF-8, console is ACP) ---------------- */

/* Truncate a UTF-8 string without splitting a multi-byte sequence. */
static void utf8_trunc(char* s, size_t maxLen) {
    size_t n = strlen(s);
    if (n <= maxLen) return;
    size_t cut = maxLen;
    while (cut > 0 && (((unsigned char)s[cut]) & 0xC0) == 0x80) cut--;
    s[cut] = '\0';
}

/* Bytes -> UTF-8. Valid UTF-8 input passes through; anything else is
 * assumed to be console ACP (GBK on zh-CN) and converted. Returns 0 on
 * success. */
static int smart_to_utf8(const char* in, size_t inLen, char* out, size_t outCap) {
    if (outCap == 0) return -1;
    out[0] = '\0';
    if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                            in, (int)inLen, NULL, 0) > 0) {
        size_t cp = inLen < outCap - 1 ? inLen : outCap - 1;
        memcpy(out, in, cp);
        out[cp] = '\0';
        return 0;
    }
    int wl = MultiByteToWideChar(CP_ACP, 0, in, (int)inLen, NULL, 0);
    if (wl <= 0) return -1;
    wchar_t* w = (wchar_t*)malloc((size_t)wl * sizeof(wchar_t));
    if (!w) return -1;
    MultiByteToWideChar(CP_ACP, 0, in, (int)inLen, w, wl);
    int ul = WideCharToMultiByte(CP_UTF8, 0, w, wl, NULL, 0, NULL, NULL);
    int rc = -1;
    if (ul > 0 && (size_t)ul < outCap) {
        WideCharToMultiByte(CP_UTF8, 0, w, wl, out, ul, NULL, NULL);
        out[ul] = '\0';
        rc = 0;
    }
    free(w);
    return rc;
}

/* UTF-8 -> console ACP for CreateProcessA/MessageBox-style ANSI callers.
 * Writes at most outCap bytes including the NUL. Returns 0 on success. */
static int utf8_to_acp(const char* in, char* out, size_t outCap) {
    if (outCap == 0) return -1;
    out[0] = '\0';
    int wl = MultiByteToWideChar(CP_UTF8, 0, in, -1, NULL, 0);
    if (wl <= 0) { _snprintf(out, outCap, "%s", in); out[outCap - 1] = '\0'; return -1; }
    wchar_t* w = (wchar_t*)malloc((size_t)wl * sizeof(wchar_t));
    if (!w) return -1;
    MultiByteToWideChar(CP_UTF8, 0, in, -1, w, wl);
    int al = WideCharToMultiByte(CP_ACP, 0, w, wl, NULL, 0, NULL, NULL);
    int rc = -1;
    if (al > 0 && (size_t)al <= outCap) {
        WideCharToMultiByte(CP_ACP, 0, w, wl, out, al, NULL, NULL);
        rc = 0;
    }
    free(w);
    return rc;
}

/* ---------------- target IP-range filter ---------------- */

static int sk_parse_v4(const char* s, uint32_t* hostOrder) {
    struct in_addr a;
    if (inet_pton(AF_INET, s, &a) != 1) return 0;
    *hostOrder = ntohl(a.s_addr);
    return 1;
}

/* One item: "a.b.c.d" | "a.b.c.d-e" | "a.b.c.d-a.b.c.e". */
static int sk_parse_range_item(const char* item, size_t len,
                               uint32_t* lo, uint32_t* hi) {
    char buf[64];
    if (len == 0 || len >= sizeof(buf)) return 0;
    memcpy(buf, item, len);
    buf[len] = '\0';

    char* dash = strchr(buf, '-');
    uint32_t a;
    if (!dash) {
        if (!sk_parse_v4(buf, &a)) return 0;
        *lo = *hi = a;
        return 1;
    }
    *dash = '\0';
    const char* suffix = dash + 1;
    if (!sk_parse_v4(buf, &a)) return 0;

    uint32_t b;
    if (sk_parse_v4(suffix, &b)) {
        /* full-range form */
    } else {
        /* short form: suffix replaces the last octet */
        size_t sl = strlen(suffix);
        if (sl == 0 || sl > 3) return 0;
        for (size_t i = 0; i < sl; ++i)
            if (suffix[i] < '0' || suffix[i] > '9') return 0;
        char* lastdot = strrchr(buf, '.');
        if (!lastdot) return 0;
        size_t keep = (size_t)(lastdot - buf) + 1;
        if (keep + sl >= sizeof(buf)) return 0;
        buf[keep + sl] = '\0';
        memmove(buf + keep + sl - sl, suffix, sl);   /* place suffix after prefix */
        /* buf now reads "a.b.c." + suffix (bytes after keep+sl are cut) */
        if (!sk_parse_v4(buf, &b)) return 0;
    }
    *lo = a < b ? a : b;
    *hi = a < b ? b : a;
    return 1;
}

static int sk_is_target_sep(char c) {
    return c == ',' || c == ';' || c == ' ' || c == '\t' ||
           c == '\r' || c == '\n';
}

static int sk_ip_in_targets(uint32_t ip, const char* targets) {
    const char* p = targets;
    while (*p) {
        while (*p && sk_is_target_sep(*p)) p++;
        if (!*p) break;
        const char* start = p;
        while (*p && !sk_is_target_sep(*p)) p++;
        uint32_t lo, hi;
        if (sk_parse_range_item(start, (size_t)(p - start), &lo, &hi) &&
            ip >= lo && ip <= hi)
            return 1;
    }
    return 0;
}

/* 1 = this host matches the targets list; empty list = no filter. */
static int sk_host_matches_targets(const char* targets) {
    while (*targets && sk_is_target_sep(*targets)) targets++;
    if (!targets[0]) return 1;

    char host[256];
    if (gethostname(host, (int)sizeof(host)) != 0) return 0;
    struct addrinfo hints, *res = NULL;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    if (getaddrinfo(host, NULL, &hints, &res) != 0) return 0;
    int hit = 0;
    for (struct addrinfo* ai = res; ai; ai = ai->ai_next) {
        if (ai->ai_family != AF_INET || !ai->ai_addr) continue;
        uint32_t ip = ntohl(((struct sockaddr_in*)ai->ai_addr)->sin_addr.s_addr);
        if (sk_ip_in_targets(ip, targets)) { hit = 1; break; }
    }
    freeaddrinfo(res);
    return hit;
}

/* ---------------- replies ---------------- */

static void send_reply(const struct sockaddr_in* to, long long task_id,
                       const char* st, long long rc, const char* info) {
    char esc_info[600], esc_host[128];
    if (sk_json_escape(info, esc_info, sizeof(esc_info)) != 0) esc_info[0] = '\0';
    if (sk_json_escape(g_host, esc_host, sizeof(esc_host)) != 0) esc_host[0] = '\0';

    char json[900];
    _snprintf(json, sizeof(json),
              "{\"task_id\":%lld,\"host\":\"%s\",\"st\":\"%s\",\"rc\":%lld,\"info\":\"%s\"}",
              task_id, esc_host, st, rc, esc_info);
    json[sizeof(json) - 1] = '\0';

    uint8_t pkt[SK_MAX_PACKET];
    size_t n = sk_build_packet(SK_MSG_REPLY, json, g_key, pkt, sizeof(pkt));
    if (n == 0) return;
    sendto(g_replySock, (const char*)pkt, (int)n, 0,
           (const struct sockaddr*)to, sizeof(*to));
}

/* ---------------- actions ---------------- */

static DWORD WINAPI msg_thread(LPVOID param) {
    wchar_t* wtext = (wchar_t*)param;
    MessageBoxW(NULL, wtext, L"\u901a\u77e5",   /* 通知 */
                MB_OK | MB_ICONINFORMATION | MB_TOPMOST | MB_SETFOREGROUND);
    free(wtext);
    return 0;
}

static void do_msg(const char* textUtf8) {
    int wl = MultiByteToWideChar(CP_UTF8, 0, textUtf8, -1, NULL, 0);
    if (wl <= 0) return;
    wchar_t* w = malloc((size_t)wl * sizeof(wchar_t));
    if (!w) return;
    MultiByteToWideChar(CP_UTF8, 0, textUtf8, -1, w, wl);
    HANDLE t = CreateThread(NULL, 0, msg_thread, w, 0, NULL);
    if (t) CloseHandle(t);
}

static void do_open_url(const char* url) {
    char buf[1500];
    /* quote the exe path, leave the url unquoted (no spaces allowed in it) */
    _snprintf(buf, sizeof(buf), "\"%s\" %s", EDGE_PATH, url);
    buf[sizeof(buf) - 1] = '\0';
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, AGENT_DIR, &si, &pi)) {
        /* fallback: default browser via shell */
        _snprintf(buf, sizeof(buf), "start \"\" %s", url);
        buf[sizeof(buf) - 1] = '\0';
        run_hidden(buf);
        return;
    }
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
}

static void do_power(const char* mode) {
    if (!strcmp(mode, "off"))          run_hidden("shutdown /s /t 5");
    else if (!strcmp(mode, "reboot"))  run_hidden("shutdown /r /t 5");
    else if (!strcmp(mode, "logoff"))  run_hidden("shutdown /l");
    else if (!strcmp(mode, "lock"))    LockWorkStation();
}

static void do_isolate(const char* allowIp, int on) {
    char buf[1400];
    if (on) {
        _snprintf(buf, sizeof(buf),
            "netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound"
            " & netsh advfirewall firewall delete rule name=SK_AllowCtrl >nul 2>&1"
            " & netsh advfirewall firewall add rule name=SK_AllowCtrl dir=in action=allow remoteip=%s"
            " & netsh advfirewall firewall add rule name=SK_AllowCtrl dir=out action=allow remoteip=%s",
            allowIp, allowIp);
    } else {
        _snprintf(buf, sizeof(buf),
            "netsh advfirewall firewall delete rule name=SK_AllowCtrl >nul 2>&1"
            " & netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound");
    }
    buf[sizeof(buf) - 1] = '\0';
    run_hidden(buf);
}

static void do_killgames(void) {
    run_hidden("taskkill /F /T /IM msedge.exe >nul 2>&1"
               " & taskkill /F /T /IM java.exe >nul 2>&1"
               " & taskkill /F /T /IM javaw.exe >nul 2>&1");
}

/* ---------------- command dispatch ---------------- */

static void handle_command(const char* json, const struct sockaddr_in* from) {
    long long task_id = sk_json_get_int(json, "task_id", 0);

    /* Target filter: the command carries the controller-side IP range box.
     * If this host's own IPv4 is not inside, stay silent and do nothing. */
    {
        char targets[700] = "";
        sk_json_get_str(json, "targets", targets, sizeof(targets));
        if (!sk_host_matches_targets(targets)) return;
    }

    long long ts      = sk_json_get_int(json, "ts", 0);
    long long rport   = sk_json_get_int(json, "reply_port", 0);

    char action[32] = "", cmd[900] = "", text[512] = "", url[600] = "";
    char mode[16] = "", allow_ip[40] = "";
    sk_json_get_str(json, "action", action, sizeof(action));
    sk_json_get_str(json, "cmd", cmd, sizeof(cmd));
    sk_json_get_str(json, "text", text, sizeof(text));
    sk_json_get_str(json, "url", url, sizeof(url));
    sk_json_get_str(json, "mode", mode, sizeof(mode));
    sk_json_get_str(json, "allow_ip", allow_ip, sizeof(allow_ip));

    /* Protocol strings are UTF-8; ANSI execution paths want console ACP. */
    {
        char conv[900];
        if (cmd[0] && utf8_to_acp(cmd, conv, sizeof(conv)) == 0) strcpy(cmd, conv);
        char conv2[512];
        if (text[0] && utf8_to_acp(text, conv2, sizeof(conv2)) == 0) strcpy(text, conv2);
        char conv3[600];
        if (url[0] && utf8_to_acp(url, conv3, sizeof(conv3)) == 0) strcpy(url, conv3);
    }

    /* reply destination: dynamic port from the command, controller address */
    struct sockaddr_in to = *from;
    if (rport > 0 && rport < 65536) to.sin_port = htons((u_short)rport);

    int64_t now = 0; sk_cur_time_utc(&now);
    if (ts != 0 && (now - ts > SK_REPLAY_WINDOW || ts - now > SK_REPLAY_WINDOW)) {
        send_reply(&to, task_id, "err", -1, "ts out of window");
        return;
    }

    if (!strcmp(action, "ping")) {
        send_reply(&to, task_id, "ok", 0, "alive");
    } else if (!strcmp(action, "exec")) {
        run_hidden(cmd);
        send_reply(&to, task_id, "ok", 0, "started");
    } else if (!strcmp(action, "exec_wait")) {
        char out[4096]; size_t outLen = 0;
        out[0] = '\0';
        int rc = run_capture(cmd, 30000, out, sizeof(out) - 1, &outLen);
        out[outLen < sizeof(out) - 1 ? outLen : sizeof(out) - 1] = '\0';
        if (outLen > 350) { out[350] = '\0'; }
        /* console bytes -> UTF-8 so the JSON reply stays valid */
        char utf8[1100];
        if (smart_to_utf8(out, strlen(out), utf8, sizeof(utf8)) != 0) utf8[0] = '\0';
        utf8_trunc(utf8, 520);
        /* rc is unreliable when truncated by pipe cap; report length too */
        char info[600];
        _snprintf(info, sizeof(info), "rc=%d len=%u out=%s",
                  rc, (unsigned)outLen, utf8);
        info[sizeof(info) - 1] = '\0';
        send_reply(&to, task_id, "ok", rc, info);
    } else if (!strcmp(action, "killgames")) {
        do_killgames();
        send_reply(&to, task_id, "ok", 0, "edge+java killed");
    } else if (!strcmp(action, "msg")) {
        do_msg(text);
        send_reply(&to, task_id, "ok", 0, "shown");
    } else if (!strcmp(action, "open_url")) {
        do_open_url(url);
        send_reply(&to, task_id, "ok", 0, "opened");
    } else if (!strcmp(action, "power")) {
        do_power(mode);
        send_reply(&to, task_id, "ok", 0, mode);
    } else if (!strcmp(action, "isolate")) {
        do_isolate(allow_ip[0] ? allow_ip : "0.0.0.0", 1);
        send_reply(&to, task_id, "ok", 0, "isolated");
    } else if (!strcmp(action, "unisolate")) {
        do_isolate("", 0);
        send_reply(&to, task_id, "ok", 0, "restored");
    } else {
        send_reply(&to, task_id, "err", -1, "unknown action");
    }
}

/* ---------------- entry ---------------- */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, PSTR pCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)pCmdLine; (void)nShow;

    HANDLE mutex = CreateMutexA(NULL, TRUE, "Local\\SeewoKillerAgent");
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    /* key must be deployed next to the agent before it can do anything */
    HANDLE kf = CreateFileA(KEY_FILE, GENERIC_READ, FILE_SHARE_READ, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (kf == INVALID_HANDLE_VALUE) return 1;
    DWORD rd = 0;
    if (!ReadFile(kf, g_key, SK_HMAC_LEN, &rd, NULL) || rd != SK_HMAC_LEN) {
        CloseHandle(kf); return 1;
    }
    CloseHandle(kf);

    DWORD hn = sizeof(g_host) - 1;
    GetComputerNameA(g_host, &hn);

    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return 1;

    /* multicast listener */
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) return 1;
    BOOL reuse = TRUE;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

    struct sockaddr_in addr;
    ZeroMemory(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(SK_MCAST_PORT);
    if (bind(sock, (const struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR)
        return 1;

    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(SK_MCAST_GROUP);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                   (const char*)&mreq, sizeof(mreq)) == SOCKET_ERROR)
        return 1;

    /* reply socket (ephemeral source port) */
    g_replySock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    /* anti-replay ring of recent task ids */
    uint32_t seen[64] = {0};
    int seenPos = 0;

    for (;;) {
        uint8_t buf[SK_MAX_PACKET];
        struct sockaddr_in from;
        int fromLen = sizeof(from);
        int n = recvfrom(sock, (char*)buf, sizeof(buf), 0,
                         (struct sockaddr*)&from, &fromLen);
        if (n <= 0) continue;

        uint8_t msgType = 0;
        char json[SK_MAX_JSON + 1];
        if (sk_parse_packet(buf, (size_t)n, g_key, &msgType, json,
                            sizeof(json)) != 0)
            continue;                          /* bad signature: drop */
        if (msgType != SK_MSG_COMMAND) continue;

        uint32_t tid = (uint32_t)sk_json_get_int(json, "task_id", 0);
        int dup = 0;
        for (int i = 0; i < 64; ++i) if (seen[i] && seen[i] == tid) { dup = 1; break; }
        if (dup) continue;
        seen[seenPos] = tid;
        seenPos = (seenPos + 1) & 63;

        handle_command(json, &from);
    }
}
