#include <windows.h>
#include <iostream>

typedef HANDLE(WINAPI *CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileW_t OriginalCreateFileW = NULL;
HANDLE hReplaceIndexFile = NULL;
int Timer = 0;

bool InitReplaceIndex()
{
    // 获取临时目录"require('./launcher.node').load('external_index', module);"写到文件
    wchar_t tempPath[MAX_PATH];
    GetTempPathW(MAX_PATH, tempPath);

    wcscat(tempPath, L"external_index.js");

    HANDLE hFile = OriginalCreateFileW(tempPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        char buffer[1024] = "require('./launcher.node').load('external_index', module);";
        DWORD dwWrite;
        WriteFile(hFile, buffer, strlen(buffer), &dwWrite, NULL);
        CloseHandle(hFile);
    }
    return true;
}

HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{

    if (Timer > 2)
    {
        auto ret = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        return ret;
    }
    if (wcsstr(lpFileName, L"app_launcher\\index.js") && Timer > 0)
    {
        // 获取命令行参数
        LPWSTR CommandLine = GetCommandLineW();
        if (wcsstr(CommandLine, L"--enable-logging") != NULL)
        {
            // 获取环境变量NAPCAT_PATH
            LPWSTR napcatPath = _wgetenv(L"NAPCAT_PATH");
            if (napcatPath != NULL && wcslen(napcatPath) > 0)
            {
                lpFileName = napcatPath;
            }
        }
    }
    if (wcsstr(lpFileName, L"app_launcher\\index.js") != NULL && Timer == 0)
    {
        //MessageBoxW(NULL, lpFileName, L"HookedCreateFileW", MB_OK);
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);

        wcscat(tempPath, L"external_index.js");
        Timer++;
        lpFileName = tempPath;
    }
    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void HookIAT()
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
                if (*ppfn == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW"))
                {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
                    OriginalCreateFileW = (CreateFileW_t)*ppfn;
                    *ppfn = (PROC)HookedCreateFileW;
                    InitReplaceIndex();
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
void UnHookIAT()
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
                if (*ppfn == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW"))
                {
                    DWORD oldProtect;
                    VirtualProtect(ppfn, sizeof(PROC), PAGE_EXECUTE_READWRITE, &oldProtect);
                    *ppfn = (PROC)OriginalCreateFileW;
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
        HookIAT();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}