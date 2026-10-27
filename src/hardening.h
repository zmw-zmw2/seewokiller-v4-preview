#pragma once
// SeewoKiller.exe lightweight anti-reverse hardening (control side only):
//   1) compile-time XOR obfuscation: key paths / schtasks command templates
//      never appear as plain text in the binary, so strings.exe or a quick
//      IDA pass cannot reveal what the tool does;
//   2) periodic debugger detection (local + remote) that silently exits.
// Deliberately NOT applied to skagent.exe: it gets flagged by AV already
// and every extra trick only makes that worse.

#include <windows.h>
#include <string>

// XOR key baked into the type; each byte additionally shifts by i*31 so
// repeated characters never produce identical ciphertext bytes.
template <size_t N, unsigned char K>
struct SkObf {
    unsigned char d[N];
    constexpr SkObf(const char (&s)[N]) : d{} {
        for (size_t i = 0; i < N; ++i)
            d[i] = (unsigned char)s[i] ^ (unsigned char)(K + (unsigned char)(i * 31));
    }
    std::string str() const {
        std::string s;
        s.resize(N - 1);
        for (size_t i = 0; i < N - 1; ++i)
            s[i] = (char)(d[i] ^ (unsigned char)(K + (unsigned char)(i * 31)));
        return s;
    }
};

#define SK_OBF_KEY 0x5A
// Decode at the call site; the binary holds ciphertext only.
#define SK_OBF(lit) SkObf<sizeof(lit), SK_OBF_KEY>(lit).str()

inline bool sk_debugger_present() {
    if (IsDebuggerPresent()) return true;
    BOOL remote = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote) && remote)
        return true;
    return false;
}

inline DWORD WINAPI sk_watch_thread(LPVOID) {
    for (;;) {
        if (sk_debugger_present()) ExitProcess(0);
        Sleep(4000);
    }
    return 0;
}

// Entry check + background watcher. Silent exit on purpose: no message box
// that tells an analyst exactly which check tripped.
inline void sk_hardening_init() {
    if (sk_debugger_present()) ExitProcess(0);
    HANDLE t = CreateThread(nullptr, 0, sk_watch_thread, nullptr, 0, nullptr);
    if (t) CloseHandle(t);
}
