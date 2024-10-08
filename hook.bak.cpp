#include <Windows.h>
#include <mutex>
#include <vector>
#include <psapi.h>
#include <cstdint>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <windows.h>
#include <stdio.h>
LPWSTR napcat_package = _wgetenv(L"NAPCAT_PATCH_PACKAGE");
LPWSTR napcat_load = _wgetenv(L"NAPCAT_LOAD_PATH");
void PrintBuffer(void *pBuff, unsigned int nLen)
{
    if (NULL == pBuff || 0 == nLen)
    {
        return;
    }

    const int nBytePerLine = 16;
    unsigned char *p = (unsigned char *)pBuff;
    char szHex[3 * nBytePerLine + 1] = {0};
    char result[4096] = {0}; // 假设结果不会超过4096字节
    char *pResult = result;

    pResult += sprintf(pResult, "-----------------begin-------------------\n");
    for (unsigned int i = 0; i < nLen; ++i)
    {
        int idx = 3 * (i % nBytePerLine);
        if (0 == idx)
        {
            memset(szHex, 0, sizeof(szHex));
        }
#ifdef WIN32
        sprintf_s(&szHex[idx], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#else
        snprintf(&szHex[idx], 4, "%02x ", p[i]); // buff长度要多传入1个字节
#endif

        // 以16个字节为一行，进行打印
        if (0 == ((i + 1) % nBytePerLine))
        {
            pResult += sprintf(pResult, "%s\n", szHex);
        }
    }

    // 打印最后一行未满16个字节的内容
    if (0 != (nLen % nBytePerLine))
    {
        pResult += sprintf(pResult, "%s\n", szHex);
    }

    pResult += sprintf(pResult, "------------------end-------------------\n");

    MessageBoxA(NULL, result, "Buffer Content", MB_OK);
}
BYTE OldCode[12] = {0x00};
BYTE HookCode[12] = {0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0};
BYTE jzCode[12] = {0x0F, 0x84};
// 辅助函数：去除字符串中的所有空格
std::string RemoveSpaces(const std::string &input)
{
    std::string result;
    for (char c : input)
    {
        if (c != ' ')
        {
            result += c;
        }
    }
    return result;
}

// 辅助函数：将十六进制字符串转换为字节模式
std::vector<uint8_t> ParseHexPattern(const std::string &hexPattern)
{
    std::string cleanedPattern = RemoveSpaces(hexPattern);
    std::vector<uint8_t> pattern;
    for (size_t i = 0; i < cleanedPattern.length(); i += 2)
    {
        std::string byteStr = cleanedPattern.substr(i, 2);
        if (byteStr == "??")
        {
            pattern.push_back(0xCC); // 使用 0xCC 作为通配符
        }
        else
        {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
            pattern.push_back(byte);
        }
    }
    return pattern;
}

// 新的匹配函数，支持通配符
bool MatchPatternWithWildcard(const uint8_t *data, const std::vector<uint8_t> &pattern)
{
    for (size_t i = 0; i < pattern.size(); ++i)
    {
        if (pattern[i] != 0xCC && data[i] != pattern[i])
        {
            return false;
        }
    }
    return true;
}

uint64_t SearchRangeAddressInModule(HMODULE module, const std::string &hexPattern, uint64_t searchStartRVA = 0, uint64_t searchEndRVA = 0)
{
    HANDLE processHandle = GetCurrentProcess();
    MODULEINFO modInfo;
    if (!GetModuleInformation(processHandle, module, &modInfo, sizeof(MODULEINFO)))
    {
        return 0;
    }
    // 解析十六进制字符串为字节模式
    std::vector<uint8_t> pattern = ParseHexPattern(hexPattern);

    // 在模块内存范围内搜索模式
    uint8_t *base = static_cast<uint8_t *>(modInfo.lpBaseOfDll);
    uint8_t *searchStart = base + searchStartRVA;
    if (searchEndRVA == 0)
    {
        // 如果留空表示搜索到结束
        searchEndRVA = modInfo.SizeOfImage;
    }
    uint8_t *searchEnd = base + searchEndRVA;

    // 确保搜索范围有效
    if (searchStart >= base && searchEnd <= base + modInfo.SizeOfImage)
    {
        for (uint8_t *current = searchStart; current < searchEnd; ++current)
        {
            if (MatchPatternWithWildcard(current, pattern))
            {
                return reinterpret_cast<uint64_t>(current);
            }
        }
    }

    return 0;
}

bool HookFunction64(const char *moduleName, LPCSTR lpFuncName, LPVOID lpFunction)
{
    DWORD_PTR FuncAddress = (UINT64)GetProcAddress(GetModuleHandleA(moduleName), lpFuncName);
    DWORD OldProtect = 0;

    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy(OldCode, (LPVOID)FuncAddress, 12);     // 拷贝原始机器码指令
        *(PINT64)(HookCode + 2) = (UINT64)lpFunction; // 填充90为指定跳转地址
    }
    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode)); // 拷贝Hook机器指令
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
    return true;
}
int8_t fuckSignFunction()
{
    return 0;
}
bool HookAnyFunction64(LPVOID originFuncion, LPVOID lpFunction)
{
    DWORD_PTR FuncAddress = (UINT64)originFuncion;
    DWORD OldProtect = 0;
    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy(OldCode, (LPVOID)FuncAddress, 12);     // 拷贝原始机器码指令
        *(PINT64)(HookCode + 2) = (UINT64)lpFunction; // 填充90为指定跳转地址
    }
    memcpy((LPVOID)FuncAddress, &HookCode, sizeof(HookCode)); // 拷贝Hook机器指令
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
    return true;
}
void UnHookFunction64(const char *moduleName, LPCSTR lpFuncName)
{
    DWORD OldProtect = 0;
    UINT64 FuncAddress = (UINT64)GetProcAddress(GetModuleHandleA(moduleName), lpFuncName);
    if (VirtualProtect((LPVOID)FuncAddress, 12, PAGE_EXECUTE_READWRITE, &OldProtect))
    {
        memcpy((LPVOID)FuncAddress, OldCode, sizeof(OldCode));
    }
    VirtualProtect((LPVOID)FuncAddress, 12, OldProtect, &OldProtect);
}
char tempPathA[MAX_PATH];
wchar_t tempPath[MAX_PATH];
extern HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

std::mutex lock;

int PackageTimer = 0;
bool isCONOUTTimer = false;
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{

    lock.lock();
    UnHookFunction64("Kernel32.dll", "CreateFileW");
    if (!isCONOUTTimer & wcsstr(lpFileName, L"CONOUT$") != NULL)
    {

        HMODULE hModule = GetModuleHandle("QQNT.dll");
        if (hModule != NULL)
        {
            isCONOUTTimer = true;
            std::string pattern = "E8 ?? ?? ?? ?? 84 C0 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? F6 84 ?? ?? ?? ?? ?? ?? 74 ?? 48 8B ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ??";
            UINT64 address = SearchRangeAddressInModule(hModule, pattern);
            if (address != 0)
            {
                // 调用hook函数
                //  ptr转成str输出显示
                address = address + 17;
                // 设置内存可写
                DWORD OldProtect = 0;
                char buffer[100];
                VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
                // adress 赋值两个个字节 0x0F 0x84
                // 输出该地址前两个字节
                // PrintBuffer((void *)address, 2);
                memcpy((LPVOID)address, jzCode, 2);
                VirtualProtect((LPVOID)address, 2, OldProtect, &OldProtect);

                // sprintf(buffer, "%p", address);
                // MessageBoxA(NULL, buffer, "CreateFileW", MB_OK);
            }
        }
    }
    if (napcat_package && wcsstr(lpFileName, L"resources\\app\\package.json") != NULL)
    {
        lpFileName = napcat_package;
        // MessageBoxW(NULL, lpFileName, L"CreateFileW", MB_OK);
    }
    if (napcat_load && wcsstr(lpFileName, L"loadNapCat.js") != NULL)
    {
        lpFileName = napcat_load;
    }
    auto ret = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    HookFunction64("Kernel32.dll", "CreateFileW", MyCreateFileW);
    lock.unlock();
    return ret;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HookFunction64("Kernel32.dll", "CreateFileW", MyCreateFileW);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
// {
//   "name": "qq-chat",
//   "version": "9.9.15-28060",
//   "private": true,
//   "description": "QQ",
//   "productName": "QQ",
//   "author": {
//     "name": "Tencent",
//     "email": "QQ-Team@tencent.com"
//   },
//   "homepage": "https://im.qq.com",
//   "sideEffects": true,
//   "bin": {
//     "qd": "externals/devtools/cli/index.js"
//   },
//   "main": "./application/app_launcher/index.js",
//   "buildVersion": "28060",
//   "isPureShell": true,
//   "isByteCodeShell": true,
//   "platform": "win32",
//   "eleArch": "x64"
// }