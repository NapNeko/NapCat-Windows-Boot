#include <windows.h>
#include <iostream>

// 快速创建命令
std::string createBootCommand(std::string processName)
{
    const char *processNameInternal = processName.c_str();
    const char *commandLine = "--enable-logging";
    char *processName2 = new char[strlen(processNameInternal) + strlen(commandLine) + 1];
    strcpy(processName2, processNameInternal);
    std::string realProcessName = processName2;
    return realProcessName;
}
// 创建进程
void CreateSuspendedProcess(const char *processName, const char *dllPath)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    // 创建并挂起进程
    auto *env = GetEnvironmentStrings();
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
}
int main(int argc, char *argv[])
{
    // for (int i = 0; i < argc; i++)
    // {
    //     std::cout << "argv[" << i << "]:" << argv[i] << std::endl;
    // }
    // for (int i = 0; i < argc; i++)
    // {
    //     std::cout << argv[i] << " ";
    // }
    // std::cout << std::endl;
    // if (argc < 2)
    // {
    //     std::cerr << "Usage: " << argv[0] << " <processName> <dllPath>" << std::endl;
    //     system("pause");
    //     return 1;
    // }
    std::string bootCommand = createBootCommand("D:\\AppD\\QQNT\\QQ.exe");
    CreateSuspendedProcess(bootCommand.c_str(), "E:\\GitDev\\NapCat-Windows-Boot\\build\\hook\\Release\\NapCatWinBootHook.dll");
    return 0;
}