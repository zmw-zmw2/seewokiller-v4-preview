#pragma once
// Startup self-protection for the console machine (runs elevated).

#include <string>

struct SelfProtectReport {
    bool elevated = false;
    bool firewallOn = false;
    bool tuokong = false;       // baseline allow + block the 3 admin IPs
    bool block22 = false;
    bool block445 = false;
    bool allowSelf = false;     // inbound allow rule for this exe (receipt wall)
    bool sshdDisabled = false;
    bool rpcBlocked = false;    // inbound RPC 135 blocked (kills remote WMI/shutdown)

    std::string text() const;
};

bool SelfProtect_IsElevated();
SelfProtectReport SelfProtect_Run();   // blocking, takes a few seconds
