#include <windows.h>
#include <iostream>
#include <csignal>
#include <string>
#include <vector>

HANDLE MainProcessHandle = NULL;

std::wstring createBootCommand(const std::wstring &processName, const std::wstring &quickLogin)
{
    std::wstring processNameInternal = L"\"" + processName + L"\"";
    std::wstring commandLine = L"--enable-logging";
    std::wstring realProcessName = processNameInternal + L" " + commandLine;
    if (!quickLogin.empty())
    {
        realProcessName += L" -q " + quickLogin;
    }
    return realProcessName;
}

void CreateSuspendedProcessW(const wchar_t *processName, const wchar_t *dllPath)
{
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

    if (!CreateProcessW(NULL, (LPWSTR)processName, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPWSTR)&errorMsg,
            0,
            NULL);
        std::wcerr << L"Error Code: " << error << std::endl;
        std::wcerr << L"Process Path: " << processName << std::endl;
        std::wcerr << L"Error: " << (wchar_t *)errorMsg << std::endl;
        LocalFree(errorMsg);
        std::wcerr << L"Failed to start process." << std::endl;
        return;
    }
    MainProcessHandle = pi.hProcess;
    std::wcout << L"[NapCat Backend] Main Process ID:" << pi.dwProcessId << std::endl;

    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, 0);
    }
}

bool IsUserAnAdmin()
{
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin);
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}

void signalHandler(int signum)
{
    if (MainProcessHandle != NULL)
    {
        std::cout << "[NapCat Backend] Terminate Main Process." << std::endl;
        TerminateProcess(MainProcessHandle, 0);
    }
    exit(signum);
}

std::wstring AnsiToUtf16(const std::string &str)
{
    int size_needed = MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, str.c_str(), (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

int main(int argc, char *argv[])
{
    signal(SIGTERM, signalHandler);
    signal(SIGINT, signalHandler);
    wchar_t buffer[MAX_PATH];
    if (argc < 2)
    {
        std::cerr << "Usage: " << argv[0] << " <quickLogin>" << std::endl;
    }
    std::wstring quickLogin = argc < 2 ? L"" : AnsiToUtf16(argv[1]);
    GetModuleFileNameW(NULL, buffer, MAX_PATH);
    std::wstring currentDir = std::wstring(buffer).substr(0, std::wstring(buffer).find_last_of(L"\\/"));
    std::wstring processPath = currentDir + L"\\QQ.exe";
    std::wstring dllPath = currentDir + L"\\NapCatWinBootHook.dll";
    std::wstring bootCommand = createBootCommand(processPath, quickLogin);
    std::wcout << L"Boot Command: " << bootCommand << std::endl;
    CreateSuspendedProcessW(bootCommand.c_str(), dllPath.c_str());
    return 0;
}