#include "selfprotect.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <cstdio>

// Blocking cmd.exe /c runner; returns exit code (-1 on spawn failure).
static int RunCmd(const std::string& cmdline) {
    char buf[2048];
    _snprintf(buf, sizeof(buf), "cmd.exe /c %s", cmdline.c_str());
    buf[sizeof(buf) - 1] = '\0';
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessA(NULL, buf, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &si, &pi))
        return -1;
    WaitForSingleObject(pi.hProcess, 20000);
    DWORD rc = 0;
    GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)rc;
}

static const char* TUOKONG_IPS = "172.16.20.1,172.17.21.1,172.16.24.176";

bool SelfProtect_IsElevated() {
    HANDLE tok = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return false;
    TOKEN_ELEVATION e{};
    DWORD rl = 0;
    BOOL ok = GetTokenInformation(tok, TokenElevation, &e, sizeof(e), &rl);
    CloseHandle(tok);
    return ok && e.TokenIsElevated;
}

SelfProtectReport SelfProtect_Run() {
    SelfProtectReport r;
    r.elevated = SelfProtect_IsElevated();
    if (!r.elevated) return r;

    // dev machines: a devmode.flag next to the exe skips all protection
    // (this box is for building/testing, not for guarding)
    {
        char exe[MAX_PATH], flag[MAX_PATH];
        GetModuleFileNameA(NULL, exe, MAX_PATH);
        char* slash = strrchr(exe, '\\');
        if (slash) *(slash + 1) = '\0';
        _snprintf(flag, sizeof(flag), "%sdevmode.flag", exe);
        DWORD attr = GetFileAttributesA(flag);
        if (attr != INVALID_FILE_ATTRIBUTES) {
            r.devMode = true;
            r.firewallOn = r.tuokong = r.block22 = r.block445 =
                r.allowSelf = r.sshdDisabled = r.rpcBlocked = true;
            return r;
        }
    }

    char exe[MAX_PATH];
    GetModuleFileNameA(NULL, exe, MAX_PATH);

    // 1. make sure the firewall is on at all
    r.firewallOn = RunCmd("netsh advfirewall set allprofiles state on") == 0;

    // 2. "tuokong" baseline: default allow + block the 3 admin IPs
    r.tuokong =
        RunCmd("netsh advfirewall set allprofiles firewallpolicy "
               "allowinbound,allowoutbound") == 0 &&
        RunCmd(std::string("netsh advfirewall firewall delete rule name=Block_3_IPs "
                           ">nul 2>&1 & netsh advfirewall firewall add rule "
                           "name=Block_3_IPs dir=in action=block remoteip=") +
               TUOKONG_IPS) == 0;

    // 3. block inbound SSH/SMB towards this console
    r.block22 =
        RunCmd("netsh advfirewall firewall delete rule name=SK_Block22 >nul 2>&1 & "
               "netsh advfirewall firewall add rule name=SK_Block22 dir=in "
               "action=block protocol=TCP localport=22") == 0;
    r.block445 =
        RunCmd("netsh advfirewall firewall delete rule name=SK_Block445 >nul 2>&1 & "
               "netsh advfirewall firewall add rule name=SK_Block445 dir=in "
               "action=block protocol=TCP localport=445") == 0;

    // 4. allow ourselves inbound (reply wall + future inbound use)
    r.allowSelf =
        RunCmd(std::string("netsh advfirewall firewall delete rule name=SeewoKiller "
                           ">nul 2>&1 & netsh advfirewall firewall add rule "
                           "name=SeewoKiller dir=in action=allow program=\"") +
               exe + "\"") == 0;

    // 5. this box never needs to be an SSH server
    int cfg = RunCmd("sc stop sshd >nul 2>&1 & sc config sshd start= disabled");
    int probe = RunCmd("sc query sshd | findstr /i STATE >nul 2>&1");
    r.sshdDisabled = (cfg == 0) || (probe != 0);   // absent service is fine

    // 6. kill the last remote-shutdown path: inbound RPC endpoint mapper.
    //    (the old "occupy shutdown slot with /t 10y" trick does not survive
    //    modern Windows: /t caps at 1 year, which makes the pending shutdown
    //    a real time bomb - replaced by a durable network block)
    r.rpcBlocked = RunCmd(
        "netsh advfirewall firewall delete rule name=SK_BlockRPC135 >nul 2>&1 & "
        "netsh advfirewall firewall add rule name=SK_BlockRPC135 dir=in "
        "action=block protocol=TCP localport=135") == 0;

    return r;
}

std::string SelfProtectReport::text() const {
    if (devMode)
        return "[i] \u5f00\u53d1\u6a21\u5f0f(devmode.flag)\uff0c\u8df3\u8fc7\u81ea\u9632\u62a4\r\n";
    if (!elevated)
        return "[!] \u975e\u7ba1\u7406\u5458\u8fd0\u884c\uff0c\u81ea\u9632\u62a4\u672a\u5f00\u542f\r\n";
    std::string s;
    auto item = [&s](const char* name, bool ok) {
        s += ok ? "[+] " : "[-] ";
        s += name;
        s += "\r\n";
    };
    item("\u9632\u706b\u5899\u5df2\u5f00\u542f", firewallOn);
    item("\u8131\u63a7\u57fa\u7ebf\u5df2\u5e94\u7528(\u5c01\u7ba1\u7406IP)", tuokong);
    item("22/445 \u5165\u7ad9\u5df2\u5c01\u7981", block22 && block445);
    item("\u63a7\u5236\u53f0\u81ea\u8eab\u5df2\u653e\u884c", allowSelf);
    item("sshd \u5df2\u505c\u7528/\u4e0d\u5b58\u5728", sshdDisabled);
    item("RPC 135 \u5165\u7ad9\u5df2\u5c01\u7981(\u8fdc\u7a0b\u5173\u673a\u6b7b\u8def)", rpcBlocked);
    return s;
}
