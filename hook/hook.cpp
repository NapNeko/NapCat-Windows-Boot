#include <windows.h>
#include <iostream>

typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
CreateFileW_t OriginalCreateFileW = NULL;

HANDLE WINAPI HookedCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    std::wcout << L"CreateFileW called with: " << lpFileName << std::endl;
    MessageBoxExW(NULL, lpFileName, L"CreateFileW called with:", MB_OK, 0);
    return OriginalCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

void HookIAT() {
    HMODULE hModule = GetModuleHandle(NULL);
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDesc->Name) {
        LPCSTR pszModName = (LPCSTR)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(pszModName, "kernel32.dll") == 0) {
            PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            while (pThunk->u1.Function) {
                PROC* ppfn = (PROC*)&pThunk->u1.Function;
                if (*ppfn == (PROC)GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateFileW")) {
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

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
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