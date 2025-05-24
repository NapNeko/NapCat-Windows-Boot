#include <windows.h>
#include <iostream>
#include <dbghelp.h>
#include <vector>
#include <string>
#include <Psapi.h>

#pragma comment(lib, "dbghelp.lib")
BYTE HookCode[12] = {0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0};
BYTE jzCode[12] = {0x0F, 0x84};
BYTE xorEax[2] = {0xb0, 0x01};

LPWSTR env_jump_patch_veify = _wgetenv(L"LAUNCHER_JUMP_VEIFY_PATCH");
LPWSTR env_patch_package = _wgetenv(L"LAUNCHER_PACKAGE_PATCH");
LPWSTR env_patch_package_hack_main = _wgetenv(L"LAUNCHER_PATCH_PACKAGE_HACK_MAIN");
LPWSTR env_patch_package_real_main = _wgetenv(L"LAUNCHER_PATCH_PACKAGE_REAL_MAIN");

typedef HANDLE(WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);

GetProcAddress_t OriginalGetProcAddress = NULL;
CreateFileW_t OriginalCreateFileW = NULL;

void HookIATCreateFileW(HMODULE hModule);

// 辅助函数 去除字符串中的所有空格
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

// 辅助函数 将十六进制字符串转换为字节模式
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

// 支持通配符
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

bool hookVeifyNew(HMODULE hModule)
{
    try
    {
        std::string pattern = "48 3B 0D ?? ?? ?? ?? 74 06 E8 ?? ?? ?? ?? CC 89 E8 0F 28 B4 24 F0 03 00 00";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        // 调用hook函数
        //  ptr转成str输出显示
        address = address + 15;
        // 设置内存可写
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
        // adress 赋值两个个字节 0x0F 0x84
        // 输出该地址前两个字节
        //PrintBuffer((LPVOID)address, 2);
        memcpy((LPVOID)address, xorEax, 2);
        VirtualProtect((LPVOID)address, 2, OldProtect, &OldProtect);
        //PrintBuffer((LPVOID)address, 2);
        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}
bool hookVeify(HMODULE hModule)
{
    try
    {
        std::string pattern = "E8 ?? ?? ?? ?? 84 C0 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0F ?? ?? ?? ?? ?? 48 ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ?? F6 84 ?? ?? ?? ?? ?? ?? 74 ?? 48 8B ?? ?? ?? ?? ?? ?? E8 ?? ?? ?? ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        // 调用hook函数
        //  ptr转成str输出显示
        address = address + 17;
        // 设置内存可写
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
        // adress 赋值两个个字节 0x0F 0x84
        // 输出该地址前两个字节
        // PrintBuffer((void *)address, 2);
        memcpy((LPVOID)address, jzCode, 2);
        VirtualProtect((LPVOID)address, 2, OldProtect, &OldProtect);
        return true;
    }
    catch (const std::exception &e)
    {
        return false;
    }
}

void initLauncher(HMODULE hModule)
{

    bool patchVeify = hookVeify(hModule);
    std::cout << "patchVeify: " << patchVeify << std::endl;

    if (env_patch_package != NULL)
    {
        HookIATCreateFileW(hModule);
    }
}
void initLauncherNew(HMODULE hModule)
{

    bool patchVeify = hookVeifyNew(hModule);
    std::cout << "patchVeify: " << patchVeify << std::endl;

    if (env_patch_package != NULL)
    {
        HookIATCreateFileW(hModule);
    }
}

FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    // 判断lpProcName是否为Null是否可读
    if (IsBadReadPtr(lpProcName, 1))
    {
        return NULL;
    }
    // 判断lpProcName是否为Null
    if (lpProcName == NULL)
    {
        return NULL;
    }
    if (strcmp(lpProcName, "ExportedContentMain") == 0)
    {
        if (hModule != NULL)
        {
            initLauncherNew(hModule);
        }
    }
    else if (strcmp(lpProcName, "QQMain") == 0)
    {
        if (hModule != NULL)
        {
            initLauncher(hModule);
        }
    }

    // system("pause");
    return OriginalGetProcAddress(hModule, lpProcName);
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName,
    DWORD dwDesiredAccess,
    DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes,
    HANDLE hTemplateFile)
{
    // std::wcout << L"Hooked CreateFileW: " << lpFileName << std::endl;

    if (env_patch_package && wcsstr(lpFileName, L"resources\\app\\package.json") != NULL)
    {

        lpFileName = env_patch_package;
        return CreateFileW(
            lpFileName,
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            dwFlagsAndAttributes,
            hTemplateFile);
        // return OriginalCreateFileW(lpFileName, GENERIC_READ, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    }
    if (env_patch_package_hack_main && env_patch_package_real_main && wcsstr(lpFileName, env_patch_package_hack_main) != NULL)
    {
        lpFileName = env_patch_package_real_main;
    }
    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}
void HookIATMainGetProcAddress()
{
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImportDesc->Name)
    {
        LPCSTR pszModName = (LPCSTR)((BYTE *)hModule + pImportDesc->Name);
        if (_stricmp(pszModName, "kernel32.dll") == 0)
        {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function)
            {
                PROC *ppfn = (PROC *)&pThunk->u1.Function;
                if (*ppfn == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress"))
                {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
                    OriginalGetProcAddress = (GetProcAddress_t)*ppfn;
                    *ppfn = (PROC)HookedGetProcAddress;
                    VirtualProtect(ppfn, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
            }
            break;
        }
        pImportDesc++;
    }
}
void HookIATCreateFileW(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hModule + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    while (pImportDesc->Name)
    {
        LPCSTR pszModName = (LPCSTR)((BYTE *)hModule + pImportDesc->Name);
        if (_stricmp(pszModName, "kernel32.dll") == 0)
        {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE *)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function)
            {
                PROC *ppfn = (PROC *)&pThunk->u1.Function;
                if (*ppfn == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW"))
                {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
                    OriginalCreateFileW = (CreateFileW_t)*ppfn;
                    *ppfn = (PROC)HookedCreateFileW;
                    VirtualProtect(ppfn, sizeof(PROC), oldProtect, &oldProtect);
                    break;
                }
                pThunk++;
            }
            break;
        }
        pImportDesc++;
    }
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        HookIATMainGetProcAddress(); // 拦截QQNT.dll加载时机
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}