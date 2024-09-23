#include <Windows.h>
#include <vector>
#include <psapi.h>
#include <string>

LPWSTR napcat_package = _wgetenv(L"NAPCAT_PATCH_PACKAGE");
LPWSTR napcat_load = _wgetenv(L"NAPCAT_LOAD_PATH");

typedef HANDLE(WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef FARPROC(WINAPI *GetProcAddress_t)(HMODULE, LPCSTR);

GetProcAddress_t OriginalGetProcAddress = NULL;
CreateFileW_t OriginalCreateFileW = NULL;

BYTE OldCode[12] = {0x00};
BYTE HookCode[12] = {0x48, 0xB8, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0xFF, 0xE0};
BYTE jzCode[12] = {0x0F, 0x84};

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
//HookedGetProcAddress
FARPROC WINAPI HookedGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
}
void HookIATMainGetProcAddress()
{
    // AllocConsole();
    // freopen("CONOUT$", "w", stdout);
    // std::wcout << env_patch_package_hack_main << std::endl;
    // std::wcout << env_patch_package_real_main << std::endl;
    // std::wcout << env_patch_package << std::endl;
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
int PackageTimer = 0;
bool isCONOUTTimer = false;
HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{

    if (!isCONOUTTimer & (wcsstr(lpFileName, L"CONOUT$") != NULL))
    {

        HMODULE hModule = GetModuleHandle("QQNT.dll");
        if (hModule != NULL)
        {
            isCONOUTTimer = true;
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

            // sprintf(buffer, "%p", address);
            // MessageBoxA(NULL, buffer, "CreateFileW", MB_OK);
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
    return ret;
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
        HookIATMainGetProcAddress();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}