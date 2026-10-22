#define WIN32_LEAN_AND_MEAN
#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <libssh/libssh.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <atomic>
#include <cstdint>
#include <sstream>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <commctrl.h>

// 链接库
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "libssh2.lib")  
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")

// 兼容旧版libssh宏定义
#ifndef SSH_EXTENDED_DATA_STDERR
#define SSH_EXTENDED_DATA_STDERR 1
#endif

// 【你自行修改的配置】
const std::string SSH_PASSWORD = "";    // 测试密码
const int SSH_TIMEOUT = 2;              // 超时时间（秒）
const int SSH_PORT = 22;                // SSH端口

// 控件ID定义
#define IDC_STATIC_IPLIST     1001
#define IDC_EDIT_IPLIST       1002
#define IDC_STATIC_USERNAME   1003
#define IDC_EDIT_USERNAME     1004
#define IDC_STATIC_DELAY      1005
#define IDC_EDIT_DELAY        1006
#define IDC_STATIC_COMMAND    1007
#define IDC_EDIT_COMMAND      1008
#define IDC_BUTTON_SHUTDOWN   1009
#define IDC_BUTTON_DISCONNECT 1010
#define IDC_BUTTON_CONTROLLED 1011
#define IDC_BUTTON_EXECUTE    1012
#define IDC_EDIT_OUTPUT       1013
#define IDC_PROGRESS          1014

// 自定义消息
#define WM_UPDATE_OUTPUT      (WM_USER + 1)
#define WM_UPDATE_PROGRESS    (WM_USER + 2)

// 颜色定义（深色蓝黑主题）
const COLORREF COLOR_BG = RGB(20, 25, 35);           // 主背景 - 深蓝黑
const COLORREF COLOR_CARD = RGB(30, 35, 45);        // 卡片背景 - 稍亮蓝黑
const COLORREF COLOR_PRIMARY = RGB(0, 120, 215);    // 主色调 - 微软蓝
const COLORREF COLOR_PRIMARY_DARK = RGB(0, 90, 180); // 主色调深色
const COLORREF COLOR_SUCCESS = RGB(0, 200, 83);     // 成功色 - 亮绿
const COLORREF COLOR_DANGER = RGB(255, 40, 40);     // 危险色 - 亮红
const COLORREF COLOR_WARNING = RGB(255, 185, 0);    // 警告色 - 金黄
const COLORREF COLOR_TEXT = RGB(220, 220, 220);     // 主文本 - 浅灰
const COLORREF COLOR_TEXT_SECONDARY = RGB(160, 160, 160); // 次要文本
const COLORREF COLOR_BORDER = RGB(50, 55, 65);      // 边框色
const COLORREF COLOR_INPUT_BG = RGB(25, 30, 40);    // 输入框背景
const COLORREF COLOR_INPUT_BORDER = RGB(60, 65, 75);// 输入框边框
const COLORREF COLOR_BUTTON_BG = RGB(40, 45, 55);   // 按钮背景
const COLORREF COLOR_BUTTON_HOVER = RGB(50, 55, 65);// 按钮悬停
const COLORREF COLOR_BUTTON_PRESSED = RGB(30, 35, 45); // 按钮按下

// 全局变量
HWND hEditIPList, hEditUsername, hEditDelay, hEditCommand, hEditOutput;
HWND hProgressBar;
HFONT hFontNormal, hFontBold, hFontMono, hFontTitle;
HBRUSH hbrBackground, hbrCardBg, hbrInputBg, hbrButtonBg;
HPEN hPenBorder;
std::atomic<int> g_currentProgress{ 0 };
std::atomic<int> g_totalIPs{ 0 };

// SSH执行结果结构体
struct SSHResult {
    std::string ip;
    bool success;
    std::string output;
    std::string error;
};

// 输出数据结构体
struct OutputData {
    std::string text;
};

/**
 * 错误日志函数
 */
void WriteLog(const std::string& message) {
    std::ofstream logFile("debug.log", std::ios::app);
    if (logFile.is_open()) {
        logFile << "[" << __TIME__ << "] " << message << std::endl;
        logFile.close();
    }
    OutputDebugStringA(("SeewoKiller: " + message + "\n").c_str());
}

/**
 * 宽字符转GBK
 */
std::string WstringToGbk(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int bufSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (bufSize <= 0) return "";
    std::string str(bufSize, 0);
    WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), -1, &str[0], bufSize, nullptr, nullptr);
    str.pop_back();
    return str;
}

/**
 * GBK转宽字符
 */
std::wstring GbkToWstring(const std::string& str) {
    if (str.empty()) return L"";
    int bufSize = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, nullptr, 0);
    if (bufSize <= 0) return L"";
    std::wstring wstr(bufSize, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &wstr[0], bufSize);
    wstr.pop_back();
    return wstr;
}

/**
 * 生成连续IP范围
 */
std::vector<std::string> GenerateIPRange(const std::string& startIP, const std::string& endIP) {
    WriteLog("Generating IP range from " + startIP + " to " + endIP);
    std::vector<std::string> ipList;
    in_addr startAddr, endAddr;

    if (inet_pton(AF_INET, startIP.c_str(), &startAddr) != 1 ||
        inet_pton(AF_INET, endIP.c_str(), &endAddr) != 1) {
        WriteLog("Invalid IP format in range: " + startIP + "-" + endIP);
        return ipList;
    }

    uint32_t start = ntohl(startAddr.s_addr);
    uint32_t end = ntohl(endAddr.s_addr);

    for (uint32_t ipInt = start; ipInt <= end; ++ipInt) {
        in_addr addr;
        addr.s_addr = htonl(ipInt);
        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr, ipStr, INET_ADDRSTRLEN);
        ipList.emplace_back(ipStr);
    }

    WriteLog("Generated " + std::to_string(ipList.size()) + " IPs");
    return ipList;
}

/**
 * 解析IP范围缩写
 */
std::vector<std::string> ParseShortRange(const std::string& rangeStr) {
    WriteLog("Parsing IP range: " + rangeStr);
    std::vector<std::string> result;
    size_t dashPos = rangeStr.find('-');
    if (dashPos == std::string::npos) {
        result.push_back(rangeStr);
        return result;
    }

    std::string prefix = rangeStr.substr(0, dashPos);
    std::string suffix = rangeStr.substr(dashPos + 1);

    size_t lastDot = prefix.find_last_of('.');
    if (lastDot == std::string::npos) {
        result.push_back(rangeStr);
        return result;
    }

    std::string ipPrefix = prefix.substr(0, lastDot + 1);
    std::string startNumStr = prefix.substr(lastDot + 1);
    std::string endNumStr = suffix;

    if (!std::all_of(startNumStr.begin(), startNumStr.end(), ::isdigit) ||
        !std::all_of(endNumStr.begin(), endNumStr.end(), ::isdigit)) {
        return GenerateIPRange(prefix, suffix);
    }

    int startNum = std::stoi(startNumStr);
    int endNum = std::stoi(endNumStr);

    if (startNum > endNum) std::swap(startNum, endNum);

    for (int i = startNum; i <= endNum; ++i) {
        result.push_back(ipPrefix + std::to_string(i));
    }

    return result;
}

/**
 * 解析IP列表
 */
std::vector<std::string> ParseIPList(const std::string& input) {
    WriteLog("Parsing IP list: " + input);
    std::vector<std::string> ipList;
    std::istringstream iss(input);
    std::string line;

    while (std::getline(iss, line)) {
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        if (line.empty()) continue;

        std::istringstream lineIss(line);
        std::string item;
        while (std::getline(lineIss, item, ',')) {
            item.erase(item.find_last_not_of(" \t") + 1);
            item.erase(0, item.find_first_not_of(" \t"));
            if (item.empty()) continue;

            std::vector<std::string> rangeIPs = ParseShortRange(item);
            ipList.insert(ipList.end(), rangeIPs.begin(), rangeIPs.end());
        }
    }

    std::sort(ipList.begin(), ipList.end());
    ipList.erase(std::unique(ipList.begin(), ipList.end()), ipList.end());

    WriteLog("Total parsed IPs: " + std::to_string(ipList.size()));
    return ipList;
}

/**
 * 单个SSH连接执行
 */
SSHResult SSHConnect(const std::string& ip, const std::string& username, const std::string& command) {
    WriteLog("SSH connecting to " + ip + " with username " + username + " and command: " + command);
    SSHResult result{ ip, false, "", "" };
    ssh_session session = nullptr;

    try {
        session = ssh_new();

        if (!session) {
            result.error = "创建SSH会话失败";
            WriteLog("SSH session creation failed for " + ip);
            return result;
        }

        int port = SSH_PORT;
        int logLevel = SSH_LOG_NOLOG;
        ssh_options_set(session, SSH_OPTIONS_HOST, ip.c_str());
        ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
        ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &SSH_TIMEOUT);
        ssh_options_set(session, SSH_OPTIONS_LOG_VERBOSITY, &logLevel);
        ssh_options_set(session, SSH_OPTIONS_PORT, &port);

        // 连接
        WriteLog("Attempting SSH connect to " + ip);
        int rc = ssh_connect(session);
        if (rc != SSH_OK) {
            result.error = "SSH连接失败：" + std::string(ssh_get_error(session));
            WriteLog("SSH connect failed for " + ip + ": " + result.error);
            ssh_free(session);
            return result;
        }

        // 认证
        WriteLog("Attempting SSH auth for " + ip);
        rc = ssh_userauth_password(session, nullptr, SSH_PASSWORD.c_str());
        if (rc != SSH_AUTH_SUCCESS) {
            result.error = "认证失败：" + std::string(ssh_get_error(session));
            WriteLog("SSH auth failed for " + ip + ": " + result.error);
            ssh_disconnect(session);
            ssh_free(session);
            return result;
        }

        // 创建通道执行命令
        WriteLog("Creating SSH channel for " + ip);
        ssh_channel channel = ssh_channel_new(session);
        if (!channel) {
            result.error = "创建通道失败";
            WriteLog("Channel creation failed for " + ip);
            ssh_disconnect(session);
            ssh_free(session);
            return result;
        }

        rc = ssh_channel_open_session(channel);
        if (rc != SSH_OK) {
            result.error = "打开会话失败：" + std::string(ssh_get_error(session));
            WriteLog("Channel open failed for " + ip + ": " + result.error);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            return result;
        }

        WriteLog("Executing command on " + ip + ": " + command);
        rc = ssh_channel_request_exec(channel, command.c_str());
        if (rc != SSH_OK) {
            result.error = "执行命令失败：" + std::string(ssh_get_error(session));
            WriteLog("Command execution failed for " + ip + ": " + result.error);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            return result;
        }

        // 读取输出
        char buffer[4096];
        rc = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        while (rc > 0) {
            result.output.append(buffer, rc);
            rc = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
        }

        // 读取错误
        rc = ssh_channel_read(channel, buffer, sizeof(buffer), SSH_EXTENDED_DATA_STDERR);
        while (rc > 0) {
            result.error.append(buffer, rc);
            rc = ssh_channel_read(channel, buffer, sizeof(buffer), SSH_EXTENDED_DATA_STDERR);
        }

        WriteLog("SSH operation completed for " + ip + ", output length: " + std::to_string(result.output.length()));

        // 清理资源
        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);

        result.success = true;
        return result;

    }
    catch (const std::exception& e) {
        WriteLog("Exception in SSHConnect for " + ip + ": " + std::string(e.what()));
        result.error = "异常：" + std::string(e.what());
        if (session) {
            ssh_free(session);
        }
        return result;
    }
    catch (...) {
        WriteLog("Unknown exception in SSHConnect for " + ip);
        result.error = "未知异常";
        if (session) {
            ssh_free(session);
        }
        return result;
    }
}

/**
 * 批量执行线程
 */
void BatchSSH(const std::vector<std::string>& ipList, const std::string& username,
    const std::string& command, int delay, HWND hWnd) {
    WriteLog("BatchSSH started with " + std::to_string(ipList.size()) + " IPs, username: " + username + ", delay: " + std::to_string(delay) + " seconds");

    g_totalIPs = (int)ipList.size();
    g_currentProgress = 0;

    std::string output = "解析到目标IP数量：" + std::to_string(ipList.size()) + "\r\n";
    output += "用户名：" + username + "\r\n";
    output += "命令：" + command + "\r\n";
    output += "================================\r\n";

    OutputData* pData = new OutputData{ output };
    PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pData);
    PostMessage(hWnd, WM_UPDATE_PROGRESS, 0, 0);

    if (delay > 0) {
        output = "延迟" + std::to_string(delay) + "秒后执行...\r\n";
        pData = new OutputData{ output };
        PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pData);
        WriteLog("Starting " + std::to_string(delay) + " second delay");
        std::this_thread::sleep_for(std::chrono::seconds(delay));
    }

    int successCount = 0, failedCount = 0;
    std::mutex mtx;
    const int MAX_THREADS = 8;
    std::atomic<int> activeThreads(0);
    std::vector<std::thread> threads;

    try {
        for (size_t i = 0; i < ipList.size(); ++i) {
            while (activeThreads >= MAX_THREADS) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }

            activeThreads++;
            threads.emplace_back([&, ip = ipList[i], index = i]() {
                try {
                    SSHResult result = SSHConnect(ip, username, command);
                    std::lock_guard<std::mutex> lock(mtx);

                    g_currentProgress++;
                    int progressPercent = (int)((g_currentProgress * 100) / g_totalIPs);
                    PostMessage(hWnd, WM_UPDATE_PROGRESS, progressPercent, 0);

                    std::string resultStr;
                    if (result.success) {
                        successCount++;
                        resultStr = "[+] [" + ip + "] 成功\r\n";
                        if (!result.output.empty()) {
                            resultStr += "   输出：" + result.output + "\r\n";
                        }
                    }
                    else {
                        failedCount++;
                        resultStr = "[-] [" + ip + "] 失败：" + result.error + "\r\n";
                    }

                    OutputData* pData = new OutputData{ resultStr };
                    PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pData);
                    activeThreads--;
                }
                catch (const std::exception& e) {
                    WriteLog("Exception in thread for IP " + ip + ": " + std::string(e.what()));
                    std::lock_guard<std::mutex> lock(mtx);
                    std::string resultStr = "[!] [" + ip + "] 异常：" + std::string(e.what()) + "\r\n";
                    OutputData* pData = new OutputData{ resultStr };
                    PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pData);
                    g_currentProgress++;
                    activeThreads--;
                }
                });
        }

        // 等待所有线程结束
        for (auto& t : threads) {
            if (t.joinable()) t.join();
        }

        WriteLog("All threads completed. Success: " + std::to_string(successCount) + ", Failed: " + std::to_string(failedCount));

        // 统计结果
        std::string finalStr = "\r\n================================\r\n";
        finalStr += "执行完成！\r\n";
        finalStr += "成功：" + std::to_string(successCount) + " | 失败：" + std::to_string(failedCount) + "\r\n";
        finalStr += "总计：" + std::to_string(ipList.size()) + "\r\n";
        finalStr += "时间：" + std::string(__TIME__) + "\r\n";
        OutputData* pFinalData = new OutputData{ finalStr };
        PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pFinalData);

        // 完成进度条
        PostMessage(hWnd, WM_UPDATE_PROGRESS, 100, 0);
    }
    catch (const std::exception& e) {
        WriteLog("Exception in BatchSSH: " + std::string(e.what()));
        OutputData* pErrorData = new OutputData{ "\r\n批量执行出错：" + std::string(e.what()) + "\r\n" };
        PostMessage(hWnd, WM_UPDATE_OUTPUT, 0, (LPARAM)pErrorData);
    }
}

/**
 * 创建现代按钮
 */
HWND CreateModernButton(HWND parent, const wchar_t* text, int x, int y, int width, int height, int id) {
    return CreateWindowW(L"BUTTON", text,
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON | BS_TEXT | BS_CENTER,
        x, y, width, height, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
}

/**
 * 创建现代编辑框
 */
HWND CreateModernEdit(HWND parent, const wchar_t* text, int x, int y, int width, int height, int id, bool multiline = false, bool readonly = false) {
    DWORD style = WS_VISIBLE | WS_CHILD | WS_BORDER | ES_LEFT;
    if (multiline) style |= ES_MULTILINE | WS_VSCROLL | ES_AUTOVSCROLL;
    if (readonly) style |= ES_READONLY;
    return CreateWindowW(L"EDIT", text, style, x, y, width, height, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
}

/**
 * 创建现代标签
 */
HWND CreateModernLabel(HWND parent, const wchar_t* text, int x, int y, int width, int height, int id, bool bold = false) {
    DWORD style = WS_VISIBLE | WS_CHILD | SS_LEFT;
    return CreateWindowW(L"STATIC", text, style, x, y, width, height, parent, (HMENU)(INT_PTR)id, GetModuleHandle(NULL), NULL);
}

/**
 * 窗口过程
 */
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
    case WM_CREATE: {
        WriteLog("Window created successfully");

        // 创建字体
        NONCLIENTMETRICS ncm = { sizeof(NONCLIENTMETRICS) };
        SystemParametersInfo(SPI_GETNONCLIENTMETRICS, sizeof(ncm), &ncm, 0);

        hFontNormal = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        hFontBold = CreateFontW(16, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        hFontMono = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Consolas");

        hFontTitle = CreateFontW(24, 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_DONTCARE, L"Microsoft YaHei UI");

        // 创建画刷和画笔
        hbrBackground = CreateSolidBrush(COLOR_BG);
        hbrCardBg = CreateSolidBrush(COLOR_CARD);
        hbrInputBg = CreateSolidBrush(COLOR_INPUT_BG);
        hbrButtonBg = CreateSolidBrush(COLOR_BUTTON_BG);
        hPenBorder = CreatePen(PS_SOLID, 1, COLOR_BORDER);

        // 创建标题
        HWND hTitle = CreateWindowW(L"STATIC", L"Seewo Killer",
            WS_VISIBLE | WS_CHILD | SS_CENTER,
            20, 20, 680, 40, hWnd, NULL, GetModuleHandle(NULL), NULL);
        SendMessage(hTitle, WM_SETFONT, (WPARAM)hFontTitle, TRUE);

        // 创建卡片容器
        int cardY = 80;

        // IP列表区域
        HWND hLabelIP = CreateModernLabel(hWnd, L"目标IP列表：", 40, cardY, 200, 30, IDC_STATIC_IPLIST, true);
        SendMessage(hLabelIP, WM_SETFONT, (WPARAM)hFontBold, TRUE);
        hEditIPList = CreateModernEdit(hWnd, L"172.16.20.6-12", 40, cardY + 30, 640, 100, IDC_EDIT_IPLIST, true, false);
        SendMessage(hEditIPList, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // 配置区域
        cardY += 150;
        HWND hLabelUser = CreateModernLabel(hWnd, L"SSH用户名：", 40, cardY, 120, 30, IDC_STATIC_USERNAME);
        SendMessage(hLabelUser, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
        hEditUsername = CreateModernEdit(hWnd, L"seewo", 40, cardY + 25, 150, 35, IDC_EDIT_USERNAME, false, false);
        SendMessage(hEditUsername, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        HWND hLabelDelay = CreateModernLabel(hWnd, L"执行延迟(秒)：", 210, cardY, 120, 30, IDC_STATIC_DELAY);
        SendMessage(hLabelDelay, WM_SETFONT, (WPARAM)hFontNormal, TRUE);
        hEditDelay = CreateModernEdit(hWnd, L"0", 210, cardY + 25, 80, 35, IDC_EDIT_DELAY, false, false);
        SendMessage(hEditDelay, WM_SETFONT, (WPARAM)hFontNormal, TRUE);

        // 快捷命令区域
        cardY += 70;
        HWND hLabelCmd = CreateModernLabel(hWnd, L"快捷命令：", 40, cardY, 120, 30, IDC_STATIC_COMMAND, true);
        SendMessage(hLabelCmd, WM_SETFONT, (WPARAM)hFontBold, TRUE);

        // 创建命令按钮
        CreateModernButton(hWnd, L"关机", 40, cardY + 25, 100, 35, IDC_BUTTON_SHUTDOWN);
        CreateModernButton(hWnd, L"脱控", 150, cardY + 25, 100, 35, IDC_BUTTON_DISCONNECT);
        CreateModernButton(hWnd, L"被控", 260, cardY + 25, 100, 35, IDC_BUTTON_CONTROLLED);

        // 自定义命令区域
        cardY += 70;
        HWND hLabelCustom = CreateModernLabel(hWnd, L"自定义命令：", 40, cardY, 120, 30, IDC_STATIC_COMMAND, true);
        SendMessage(hLabelCustom, WM_SETFONT, (WPARAM)hFontBold, TRUE);
        hEditCommand = CreateModernEdit(hWnd, L"whoami", 40, cardY + 25, 520, 35, IDC_EDIT_COMMAND, false, false);
        SendMessage(hEditCommand, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        // 执行按钮
        HWND hBtnExecute = CreateModernButton(hWnd, L"开始执行", 570, cardY + 25, 110, 35, IDC_BUTTON_EXECUTE);
        SendMessage(hBtnExecute, WM_SETFONT, (WPARAM)hFontBold, TRUE);

        // 进度条
        cardY += 70;
        hProgressBar = CreateWindow(PROGRESS_CLASS, NULL,
            WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
            40, cardY, 640, 25, hWnd, (HMENU)IDC_PROGRESS, GetModuleHandle(NULL), NULL);
        SendMessage(hProgressBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
        SendMessage(hProgressBar, PBM_SETBARCOLOR, 0, COLOR_PRIMARY);
        SendMessage(hProgressBar, PBM_SETBKCOLOR, 0, COLOR_CARD);

        // 输出区域
        cardY += 35;
        HWND hLabelOutput = CreateModernLabel(hWnd, L"执行输出：", 40, cardY, 120, 30, IDC_STATIC_COMMAND, true);
        SendMessage(hLabelOutput, WM_SETFONT, (WPARAM)hFontBold, TRUE);
        hEditOutput = CreateModernEdit(hWnd,
            L"Seewo Killer \n\n"
            L"使用说明：\n"
            L"* 输入IP范围:\n"
            L"* 设置SSH用户名（默认：seewo）\n"
            L"* 选择快捷命令或输入自定义命令\n"
            L"* 点击开始执行按钮\n\n"
            L"快捷命令：\n"
            L"* 关机：远程关闭计算机\n"
            L"* 脱控：断开远程控制连接\n"
            L"* 被控：恢复被控状态\n",
            40, cardY + 30, 640, 200, IDC_EDIT_OUTPUT, true, true);
        SendMessage(hEditOutput, WM_SETFONT, (WPARAM)hFontMono, TRUE);
        // 设置输出框文本上限（大值防止溢出）
        SendMessage(hEditOutput, EM_LIMITTEXT, (WPARAM)0x7FFFFFFE, 0);

        return 0;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdcStatic = (HDC)wParam;
        HWND hwndStatic = (HWND)lParam;
        int id = GetDlgCtrlID(hwndStatic);

        // 设置文本颜色
        if (id == IDC_STATIC_IPLIST || id == IDC_STATIC_COMMAND ||
            id == IDC_STATIC_USERNAME || id == IDC_STATIC_DELAY) {
            SetTextColor(hdcStatic, COLOR_TEXT);
        }
        else {
            SetTextColor(hdcStatic, COLOR_TEXT_SECONDARY);
        }

        SetBkColor(hdcStatic, COLOR_BG);
        SetBkMode(hdcStatic, TRANSPARENT);

        return (LRESULT)hbrBackground;
    }

    case WM_CTLCOLOREDIT: {
        HDC hdcEdit = (HDC)wParam;
        HWND hwndEdit = (HWND)lParam;
        int id = GetDlgCtrlID(hwndEdit);

        SetTextColor(hdcEdit, COLOR_TEXT);
        SetBkColor(hdcEdit, COLOR_INPUT_BG);

        if (id == IDC_EDIT_OUTPUT) {
            return (LRESULT)hbrInputBg;
        }

        // 创建并返回输入框背景画刷
        static HBRUSH hbrEdit = CreateSolidBrush(COLOR_INPUT_BG);
        return (LRESULT)hbrEdit;
    }

    case WM_CTLCOLORBTN: {
        HDC hdcBtn = (HDC)wParam;
        HWND hwndBtn = (HWND)lParam;
        int id = GetDlgCtrlID(hwndBtn);

        SetTextColor(hdcBtn, COLOR_TEXT);
        SetBkColor(hdcBtn, COLOR_BUTTON_BG);

        static HBRUSH hbrBtn = CreateSolidBrush(COLOR_BUTTON_BG);
        if (id == IDC_BUTTON_EXECUTE) {
            static HBRUSH hbrExecute = CreateSolidBrush(COLOR_PRIMARY);
            SetTextColor(hdcBtn, RGB(255, 255, 255));
            SetBkColor(hdcBtn, COLOR_PRIMARY);
            return (LRESULT)hbrExecute;
        }
        else if (id == IDC_BUTTON_SHUTDOWN) {
            static HBRUSH hbrShutdown = CreateSolidBrush(COLOR_DANGER);
            SetTextColor(hdcBtn, RGB(255, 255, 255));
            SetBkColor(hdcBtn, COLOR_DANGER);
            return (LRESULT)hbrShutdown;
        }

        return (LRESULT)hbrBtn;
    }

    case WM_DRAWITEM: {
        // 处理按钮自定义绘制
        LPDRAWITEMSTRUCT pDraw = (LPDRAWITEMSTRUCT)lParam;
        if (pDraw->CtlType != ODT_BUTTON) return 0;

        int id = GetDlgCtrlID(pDraw->hwndItem);
        COLORREF bgColor = COLOR_BUTTON_BG;
        COLORREF textColor = COLOR_TEXT;
        COLORREF borderColor = COLOR_BORDER;

        if (id == IDC_BUTTON_EXECUTE) {
            bgColor = COLOR_PRIMARY;
            textColor = RGB(255, 255, 255);
            borderColor = COLOR_PRIMARY_DARK;
        }
        else if (id == IDC_BUTTON_SHUTDOWN) {
            bgColor = COLOR_DANGER;
            textColor = RGB(255, 255, 255);
            borderColor = RGB(200, 30, 30);
        }
        else if (id == IDC_BUTTON_DISCONNECT) {
            bgColor = COLOR_WARNING;
            textColor = RGB(255, 255, 255);
            borderColor = RGB(220, 165, 0);
        }
        else if (id == IDC_BUTTON_CONTROLLED) {
            bgColor = COLOR_SUCCESS;
            textColor = RGB(255, 255, 255);
            borderColor = RGB(0, 180, 73);
        }

        // 绘制按钮背景
        HBRUSH hBrush = CreateSolidBrush(bgColor);
        FillRect(pDraw->hDC, &pDraw->rcItem, hBrush);
        DeleteObject(hBrush);

        // 绘制边框
        HPEN hPen = CreatePen(PS_SOLID, 1, borderColor);
        HPEN hOldPen = (HPEN)SelectObject(pDraw->hDC, hPen);
        HBRUSH hOldBrush = (HBRUSH)SelectObject(pDraw->hDC, GetStockObject(NULL_BRUSH));
        RoundRect(pDraw->hDC, pDraw->rcItem.left, pDraw->rcItem.top,
            pDraw->rcItem.right, pDraw->rcItem.bottom, 4, 4);
        SelectObject(pDraw->hDC, hOldPen);
        SelectObject(pDraw->hDC, hOldBrush);
        DeleteObject(hPen);

        // 绘制文字
        WCHAR text[100];
        GetWindowTextW(pDraw->hwndItem, text, 100);
        SetBkMode(pDraw->hDC, TRANSPARENT);
        SetTextColor(pDraw->hDC, textColor);

        HFONT hOldFont = (HFONT)SelectObject(pDraw->hDC, hFontNormal);
        if (id == IDC_BUTTON_EXECUTE) {
            SelectObject(pDraw->hDC, hFontBold);
        }

        DrawTextW(pDraw->hDC, text, -1, &pDraw->rcItem,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE);

        SelectObject(pDraw->hDC, hOldFont);

        return TRUE;
    }

    case WM_COMMAND: {
        if (LOWORD(wParam) == IDC_BUTTON_SHUTDOWN) {
            SetWindowTextW(hEditCommand, L"shutdown -s -t 0");
            WriteLog("Shutdown command filled");
        }
        else if (LOWORD(wParam) == IDC_BUTTON_DISCONNECT) {
            SetWindowTextW(hEditCommand, L"netsh advfirewall set allprofiles firewallpolicy allowinbound,allowoutbound & netsh advfirewall firewall add rule name='Block_3_IPs' dir=in action=block remoteip=172.16.20.1,172.17.21.1,172.16.24.176");
            WriteLog("Disconnect command filled");
        }
        else if (LOWORD(wParam) == IDC_BUTTON_CONTROLLED) {
            SetWindowTextW(hEditCommand, L"netsh advfirewall firewall delete rule name='Block_3_IPs'");
            WriteLog("Controlled command filled");
        }
        else if (LOWORD(wParam) == IDC_BUTTON_EXECUTE) {
            WriteLog("Execute button clicked");

            try {
                // 获取输入内容
                wchar_t ipListBuf[4096];
                GetWindowTextW(hEditIPList, ipListBuf, 4096);
                std::string ipListStr = WstringToGbk(ipListBuf);

                wchar_t usernameBuf[256];
                GetWindowTextW(hEditUsername, usernameBuf, 256);
                std::string username = WstringToGbk(usernameBuf);

                wchar_t delayBuf[256], cmdBuf[512];
                GetWindowTextW(hEditDelay, delayBuf, 256);
                GetWindowTextW(hEditCommand, cmdBuf, 512);

                // 检查输入
                std::wstring usernameWstr = usernameBuf;
                if (usernameWstr.empty()) {
                    MessageBoxW(hWnd, L"请输入SSH用户名！", L"提示", MB_ICONWARNING);
                    WriteLog("No username entered");
                    return 0;
                }

                std::wstring cmdWstr = cmdBuf;
                if (cmdWstr.empty()) {
                    MessageBoxW(hWnd, L"请选择快捷命令或输入自定义命令！", L"提示", MB_ICONWARNING);
                    WriteLog("No command entered");
                    return 0;
                }

                std::string command = WstringToGbk(cmdBuf);
                int delay = _wtoi(delayBuf);

                WriteLog("Parsing IP list: " + ipListStr);
                std::vector<std::string> ipList = ParseIPList(ipListStr);
                if (ipList.empty()) {
                    MessageBoxW(hWnd, L"未解析到有效IP！", L"提示", MB_ICONINFORMATION);
                    WriteLog("No valid IPs parsed");
                    return 0;
                }

                // 清空输出框
                SetWindowTextW(hEditOutput, L"");

                // 重置进度条
                SendMessage(hProgressBar, PBM_SETPOS, 0, 0);

                WriteLog("Starting batch SSH execution");

                // 启动后台线程
                std::thread batchThread(BatchSSH, ipList, username, command, delay, hWnd);
                batchThread.detach();
            }
            catch (const std::exception& e) {
                WriteLog("Exception in button click handler: " + std::string(e.what()));
                MessageBoxA(hWnd, ("执行出错：" + std::string(e.what())).c_str(), "错误", MB_ICONERROR);
            }
        }
        return 0;
    }

    case WM_UPDATE_OUTPUT: {
        try {
            OutputData* pData = reinterpret_cast<OutputData*>(lParam);
            if (pData) {
                wchar_t currentBuf[32768];
                GetWindowTextW(hEditOutput, currentBuf, 32768);
                std::wstring currentText = currentBuf;

                currentText += GbkToWstring(pData->text);
                SetWindowTextW(hEditOutput, currentText.c_str());

                // 滚动到底部
                SendMessageW(hEditOutput, EM_SETSEL, (WPARAM)-1, (LPARAM)-1);
                SendMessageW(hEditOutput, EM_SCROLLCARET, 0, 0);

                delete pData;
            }
        }
        catch (const std::exception& e) {
            WriteLog("Exception in WM_UPDATE_OUTPUT: " + std::string(e.what()));
        }
        return 0;
    }

    case WM_UPDATE_PROGRESS: {
        int progress = (int)wParam;
        SendMessage(hProgressBar, PBM_SETPOS, progress, 0);
        return 0;
    }

    case WM_SIZE: {
        RECT rcClient;
        GetClientRect(hWnd, &rcClient);

        // 调整输出框大小
        if (hEditOutput) {
            SetWindowPos(hEditOutput, NULL, 40, rcClient.bottom - 230,
                rcClient.right - 80, 200, SWP_NOZORDER);
        }

        // 调整进度条大小
        if (hProgressBar) {
            SetWindowPos(hProgressBar, NULL, 40, rcClient.bottom - 260,
                rcClient.right - 80, 25, SWP_NOZORDER);
        }

        return 0;
    }

    case WM_DESTROY: {
        WriteLog("Window destroyed");

        // 清理GDI对象
        if (hFontNormal) DeleteObject(hFontNormal);
        if (hFontBold) DeleteObject(hFontBold);
        if (hFontMono) DeleteObject(hFontMono);
        if (hFontTitle) DeleteObject(hFontTitle);
        if (hbrBackground) DeleteObject(hbrBackground);
        if (hbrCardBg) DeleteObject(hbrCardBg);
        if (hbrInputBg) DeleteObject(hbrInputBg);
        if (hbrButtonBg) DeleteObject(hbrButtonBg);
        if (hPenBorder) DeleteObject(hPenBorder);

        PostQuitMessage(0);
        return 0;
    }

    default:
        return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }
}

/**
 * 主函数
 */
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    try {
        WriteLog("=== Seewo Killer Starting ===");

        // 初始化Common Controls
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_WIN95_CLASSES | ICC_PROGRESS_CLASS;
        InitCommonControlsEx(&icex);

        // 初始化Winsock
        WriteLog("Initializing Winsock");
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            WriteLog("Winsock initialization failed");
            MessageBoxW(NULL, L"Winsock初始化失败", L"错误", MB_ICONERROR);
            return 1;
        }
        WriteLog("Winsock initialized successfully");

        // 初始化libssh
        WriteLog("Initializing libssh");
        int ssh_result = ssh_init();
        if (ssh_result != SSH_OK) {
            WriteLog("SSH initialization failed: " + std::to_string(ssh_result));
            MessageBoxW(NULL, L"SSH库初始化失败，请检查libssh2.dll是否存在", L"错误", MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        WriteLog("SSH initialized successfully");

        // 注册窗口类
        WriteLog("Registering window class");
        const wchar_t CLASS_NAME[] = L"SeewoKillerDark";
        WNDCLASSW wc = { 0 };
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = CLASS_NAME;
        wc.hbrBackground = CreateSolidBrush(COLOR_BG);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
        wc.style = CS_HREDRAW | CS_VREDRAW;

        if (!RegisterClassW(&wc)) {
            WriteLog("Window class registration failed");
            MessageBoxW(NULL, L"窗口类注册失败", L"错误", MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        WriteLog("Window class registered successfully");

        // 创建窗口
        WriteLog("Creating window");
        HWND hWnd = CreateWindowExW(
            0,
            CLASS_NAME,
            L"Seewo Killer ",
            WS_OVERLAPPEDWINDOW | WS_MIN`                                                   
IMIZEBOX | WS_MAXIMIZEBOX | WS_THICKFRAME,
            CW_USEDEFAULT, CW_USEDEFAULT, 760, 810,
            NULL, NULL, hInstance, NULL
        );

        if (!hWnd) {
            WriteLog("Window creation failed");
            MessageBoxW(NULL, L"窗口创建失败", L"错误", MB_ICONERROR);
            WSACleanup();
            return 1;
        }
        WriteLog("Window created successfully");

        // 显示窗口
        ShowWindow(hWnd, nCmdShow);
        UpdateWindow(hWnd);
        WriteLog("Window displayed");

        // 消息循环
        WriteLog("Starting message loop");
        MSG msg = { 0 };
        while (GetMessageW(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        WriteLog("Message loop ended");
        // 清理资源
        ssh_finalize();
        WSACleanup();
        WriteLog("=== Seewo Killer Exited ===");
        return 0;
    }
    catch (const std::exception& e) {
        WriteLog("Fatal exception in wWinMain: " + std::string(e.what()));
        MessageBoxA(NULL, ("程序异常退出：" + std::string(e.what())).c_str(), "严重错误", MB_ICONERROR);
        return 1;
    }
    catch (...) {
        WriteLog("Unknown fatal exception in wWinMain");
        MessageBoxW(NULL, L"程序发生未知异常", L"严重错误", MB_ICONERROR);
        return 1;
    }
}