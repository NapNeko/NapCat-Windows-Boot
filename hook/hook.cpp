#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <vector>
#include <psapi.h>
#include <string>
#include <atlstr.h>
// 本项目该分支用于NapCat主仓库 Windows平台启动器
LPWSTR napcat_package = _wgetenv(L"NAPCAT_PATCH_PACKAGE");
LPWSTR napcat_load = _wgetenv(L"NAPCAT_LOAD_PATH");

typedef HANDLE(WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);
typedef BOOL(WINAPI *GetFileInformationByName_t)(PCWSTR, FILE_INFO_BY_NAME_CLASS, PVOID, ULONG);

GetProcAddress_t OriginalGetProcAddress = NULL;
CreateFileW_t OriginalCreateFileW = NULL;
GetFileInformationByName_t OriginalGetFileInformationByName = NULL;
GetFileInformationByName_t OriginalKernelBaseGetFileInformationByName = NULL;

BYTE jzCode[] = {0x0F, 0x84};

void HookIATCreateFileW(HMODULE hModule);
void HookIATGetFileInformationByName(HMODULE hModule);
void HookIATGetProcAddress(HMODULE hModule);
BOOL WINAPI HookedGetFileInformationByName(PCWSTR, FILE_INFO_BY_NAME_CLASS, PVOID, ULONG);
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
        std::string pattern = "E8 ?? ?? ?? ?? E8 ?? ?? ?? ?? 84 C0 0F 85 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ??";
        UINT64 address = SearchRangeAddressInModule(hModule, pattern);
        // 调用hook函数
        //  ptr转成str输出显示
        address = address + 12;
        // 设置内存可写
        DWORD OldProtect = 0;
        VirtualProtect((LPVOID)address, 2, PAGE_EXECUTE_READWRITE, &OldProtect);
        // adress 赋值两个个字节 0x0F 0x84
        // 输出该地址前两个字节
        // PrintBuffer((LPVOID)address, 2);
        memcpy((LPVOID)address, jzCode, 2);
        VirtualProtect((LPVOID)address, 2, OldProtect, &OldProtect);
        // PrintBuffer((LPVOID)address, 2);
        return true;
    }
    catch (const std::exception &)
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
    catch (const std::exception &)
    {
        return false;
    }
}

void initLauncherNew(HMODULE hModule)
{

    bool patchVeify = hookVeifyNew(hModule);
    HookIATCreateFileW(hModule);
    HookIATGetProcAddress(hModule);
    HookIATGetFileInformationByName(hModule);
}
void initLauncher(HMODULE hModule)
{
    bool patchVeify = hookVeify(hModule);
    HookIATCreateFileW(hModule);
    HookIATGetProcAddress(hModule);
    HookIATGetFileInformationByName(hModule);
}

FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    FARPROC original = OriginalGetProcAddress(hModule, lpProcName);
    if (reinterpret_cast<ULONG_PTR>(lpProcName) <= 0xffff || original == NULL)
    {
        return original;
    }
    if (original == reinterpret_cast<FARPROC>(OriginalGetFileInformationByName) ||
        original == reinterpret_cast<FARPROC>(OriginalKernelBaseGetFileInformationByName))
    {
        return reinterpret_cast<FARPROC>(HookedGetFileInformationByName);
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
    return original;
}

void HookImport(HMODULE module, PROC original, PROC replacement)
{
    if (!module || !original)
        return;
    auto base = reinterpret_cast<BYTE *>(module);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
    auto directory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!directory.VirtualAddress || !directory.Size)
        return;
    auto importDescriptor = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(base + directory.VirtualAddress);
    for (; importDescriptor->Name; ++importDescriptor)
    {
        auto thunk = reinterpret_cast<PIMAGE_THUNK_DATA>(base + importDescriptor->FirstThunk);
        for (; thunk->u1.Function; ++thunk)
        {
            auto entry = reinterpret_cast<PROC *>(&thunk->u1.Function);
            if (*entry == original)
            {
                DWORD oldProtect;
                if (!VirtualProtect(entry, sizeof(PROC), PAGE_READWRITE, &oldProtect))
                {
                    OutputDebugStringW(L"[NapCat Hook] Failed to make import entry writable.\n");
                    continue;
                }
                InterlockedExchangePointer(reinterpret_cast<PVOID volatile *>(entry), reinterpret_cast<PVOID>(replacement));
                if (!VirtualProtect(entry, sizeof(PROC), oldProtect, &oldProtect))
                    OutputDebugStringW(L"[NapCat Hook] Failed to restore import entry protection.\n");
            }
        }
    }
}

void HookIATGetProcAddress(HMODULE hModule)
{
    HookImport(hModule, reinterpret_cast<PROC>(OriginalGetProcAddress), reinterpret_cast<PROC>(HookedGetProcAddress));
}

HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    // MessageBoxW(NULL, lpFileName, L"HookedCreateFileW", MB_OK);
    if (napcat_package && wcsstr(lpFileName, L"resources\\app\\package.json") != NULL)
    {
        // MessageBoxW(NULL, lpFileName, L"HookedCreateFileWed", MB_OK);
        lpFileName = napcat_package;
    }
    if (napcat_load && wcsstr(lpFileName, L"loadNapCat.js") != NULL)
    {
        lpFileName = napcat_load;
    }
    return CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI HookedGetFileInformationByName(PCWSTR FileName, FILE_INFO_BY_NAME_CLASS FileInformationClass, PVOID FileInfoBuffer, ULONG FileInfoBufferSize)
{
    PCWSTR actualFileName = FileName;
    if (FileName && napcat_package && wcsstr(FileName, L"resources\\app\\package.json") != NULL)
    {
        actualFileName = napcat_package;
    }
    if (FileName && napcat_load && wcsstr(FileName, L"loadNapCat.js") != NULL)
    {
        actualFileName = napcat_load;
    }

    return OriginalGetFileInformationByName(actualFileName, FileInformationClass, FileInfoBuffer, FileInfoBufferSize);
}

void HookIATGetFileInformationByName(HMODULE hModule)
{
    HookImport(hModule, reinterpret_cast<PROC>(OriginalGetFileInformationByName), reinterpret_cast<PROC>(HookedGetFileInformationByName));
    HookImport(hModule, reinterpret_cast<PROC>(OriginalKernelBaseGetFileInformationByName), reinterpret_cast<PROC>(HookedGetFileInformationByName));
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
        OriginalGetProcAddress = GetProcAddress;
        OriginalGetFileInformationByName = reinterpret_cast<GetFileInformationByName_t>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetFileInformationByName"));
        OriginalKernelBaseGetFileInformationByName = reinterpret_cast<GetFileInformationByName_t>(
            GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "GetFileInformationByName"));
        if (!OriginalGetFileInformationByName)
            OriginalGetFileInformationByName = OriginalKernelBaseGetFileInformationByName;
        HookIATGetProcAddress(GetModuleHandleW(NULL));
        HookIATGetFileInformationByName(GetModuleHandleW(NULL));
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
