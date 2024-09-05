#include <windows.h>
#include <iostream>

// 快速创建命令
std::string createBootCommand(std::string processName, std::string qucikLogin)
{
    const char *processNameInternal = processName.c_str();
    const char *commandLine = "--enable-logging";
    std::string realProcessName = processNameInternal;
    realProcessName += " ";
    realProcessName += commandLine;
    if (qucikLogin.length() > 0)
    {
        realProcessName += " -q";
        realProcessName += qucikLogin;
    }
    return realProcessName;
}
// 创建进程
void CreateSuspendedProcess(const char *processName, const char *dllPath)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    // 修改标准输出流
    si.dwFlags = STARTF_USESTDHANDLES;
    // si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    // si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    //  创建并挂起进程
    auto *env = GetEnvironmentStrings();
    // 获取命令行环境的环境变量
    if (!CreateProcessA(NULL, (LPSTR)processName, NULL, NULL, FALSE, CREATE_SUSPENDED, (LPVOID)env, NULL, &si, &pi))
    {
        std::cerr << "Failed to start process." << std::endl;
        return;
    }

    // 注入 DLL
    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    // 恢复进程
    ResumeThread(pi.hThread);
    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 关闭句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    system("pause");
    // 判断进程是否残留
    if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, 0);
    }
}
bool IsUserAnAdmin()
{
    BOOL fIsRunAsAdmin = FALSE;
    DWORD dwError = ERROR_SUCCESS;
    PSID pAdministratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &pAdministratorsGroup))
    {
        dwError = GetLastError();
    }
    else
    {
        if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin))
        {
            dwError = GetLastError();
        }
        FreeSid(pAdministratorsGroup);
    }
    return fIsRunAsAdmin;
}
int main(int argc, char *argv[])
{
    // 判断当前是否为管理员权限
    if (!IsUserAnAdmin())
    {
        std::cerr << "Please run as administrator." << std::endl;
        system("pause");
        return 1;
    }
    system("chcp 65001");
    for (int i = 0; i < argc; i++)
    {
        std::cout << "argv[" << i << "]:" << argv[i] << std::endl;
    }
    for (int i = 0; i < argc; i++)
    {
        std::cout << argv[i] << " ";
    }
    std::cout << std::endl;
    if (argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <processName> <dllPath> <quickLogin>" << std::endl;
        system("pause");
        return 1;
    }
    std::string quickLoginQQ = "";
    if (argc == 4)
    {
        quickLoginQQ = argv[3];
    }
    std::string bootCommand = createBootCommand(argv[1], quickLoginQQ);
    std::cout << "Boot Command:" << bootCommand << std::endl;
    CreateSuspendedProcess(bootCommand.c_str(), argv[2]);
    return 0;
}