#include <windows.h>
#include <iostream>
#include <csignal>
#include <signal.h>
#include <string>
#include <vector>

HANDLE MainProcessHandle = NULL;
HANDLE PipeHandle = NULL;
HANDLE ReadThread = NULL;
bool ShouldTerminate = false;

DWORD WINAPI ReadPipeThread(LPVOID lpParam)
{
    HANDLE hPipe = (HANDLE)lpParam;
    char buffer[4096];
    DWORD bytesRead;

    while (!ShouldTerminate)
    {
        if (ReadFile(hPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0)
        {
            buffer[bytesRead] = '\0';
            std::cout << buffer << std::flush;
        }
        else if (GetLastError() != ERROR_MORE_DATA)
        {
            break;
        }
    }

    return 0;
}

std::wstring createBootCommand(std::wstring processName, std::wstring qucikLogin)
{
    std::wstring processNameInternal = L"\"" + processName + L"\"";
    std::wstring commandLine = L"--enable-logging";
    std::wstring realProcessName = processNameInternal;
    realProcessName += L" ";
    realProcessName += commandLine;
    if (qucikLogin.length() > 0)
    {
        realProcessName += L" -q ";
        realProcessName += qucikLogin;
    }
    return realProcessName;
}
void CreateSuspendedProcessW(const wchar_t *processName, const wchar_t *dllPath)
{
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    // 修改标准输出流
    si.dwFlags = STARTF_USESTDHANDLES;
    // 不继承标准输入输出句柄
    si.hStdOutput = INVALID_HANDLE_VALUE;
    si.hStdError = INVALID_HANDLE_VALUE;
    si.hStdInput = INVALID_HANDLE_VALUE;
    // ACSPORT

    if (!CreateProcessW(NULL, (LPWSTR)processName, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, (LPVOID)NULL, NULL, &si, &pi))
    {
        // 输出错误信息
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
        // 输出错误代码和程序路径
        std::wcerr << L"Error Code: " << error << std::endl;
        std::wcerr << L"Process Path: " << processName << std::endl;
        std::wcerr << L"Error: " << (wchar_t *)errorMsg << std::endl;
        LocalFree(errorMsg);
        std::wcerr << L"Failed to start process." << std::endl;
        return;
    }
    MainProcessHandle = pi.hProcess;
    std::wcout << L"[NapCat Backend] Main Process ID:" << pi.dwProcessId << std::endl;

    // 步骤1: 根据进程ID创建命名管道名称
    std::wstring pipeName = L"\\\\.\\pipe\\NapCat_" + std::to_wstring(pi.dwProcessId);
    std::wcout << L"Creating pipe: " << pipeName << std::endl;

    // 创建命名管道
    PipeHandle = CreateNamedPipeW(
        pipeName.c_str(),           // 管道名称
        PIPE_ACCESS_DUPLEX,         // 读写访问
        PIPE_TYPE_MESSAGE |         // 消息类型管道
            PIPE_READMODE_MESSAGE | // 消息读取模式
            PIPE_WAIT,              // 阻塞模式
        PIPE_UNLIMITED_INSTANCES,   // 最大实例数
        1024,                       // 输出缓冲区大小
        1024,                       // 输入缓冲区大小
        0,                          // 客户端超时
        NULL                        // 默认安全属性
    );
    if (PipeHandle == INVALID_HANDLE_VALUE)
    {
        std::wcout << L"Failed to create pipe: " << GetLastError() << std::endl;
    }

    // 步骤2: 注入 DLL
    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    HANDLE pipeConnectionThread = CreateThread(
        NULL,
        0,
        [](LPVOID param) -> DWORD
        {
            HANDLE pipe = (HANDLE)param;
            std::wcout << L"[NapCat Backend] Waiting for pipe connection..." << std::endl;

            if (ConnectNamedPipe(pipe, NULL) || GetLastError() == ERROR_PIPE_CONNECTED)
            {
                std::wcout << L"[NapCat Backend] Pipe connected successfully" << std::endl;

                // 创建读取线程
                ReadThread = CreateThread(NULL, 0, ReadPipeThread, pipe, 0, NULL);
                if (ReadThread == NULL)
                {
                    std::wcout << L"Failed to create read thread: " << GetLastError() << std::endl;
                }
                else
                {
                    std::wcout << L"[NapCat Backend] Read thread started" << std::endl;
                }
            }
            else
            {
                std::wcout << L"[NapCat Backend] Failed to connect pipe: " << GetLastError() << std::endl;
            }

            return 0;
        },
        PipeHandle,
        0,
        NULL);

    if (pipeConnectionThread == NULL)
    {
        std::wcout << L"Failed to create pipe connection thread: " << GetLastError() << std::endl;
    }

    // 步骤3: 恢复进程
    ResumeThread(pi.hThread);
    std::wcout << L"[NapCat Backend] Process resumed" << std::endl;

    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);
    std::wcout << L"Process exited." << std::endl;

    // 关闭进程句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    // 关闭命名管道和读取线程
    ShouldTerminate = true;
    if (ReadThread != NULL)
    {
        WaitForSingleObject(ReadThread, 1000);
        CloseHandle(ReadThread);
        ReadThread = NULL;
    }
    if (pipeConnectionThread != NULL)
    {
        CloseHandle(pipeConnectionThread);
    }
    if (PipeHandle != NULL)
    {
        DisconnectNamedPipe(PipeHandle);
        CloseHandle(PipeHandle);
        PipeHandle = NULL;
    }

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

void signalHandler(int signum)
{
    // 先标记读取线程应该结束
    ShouldTerminate = true;

    if (MainProcessHandle != NULL)
    {
        std::cout << "[NapCat Backend] Terminate Main Process." << std::endl;
        TerminateProcess(MainProcessHandle, 0);
    }

    // 等待读取线程结束
    if (ReadThread != NULL)
    {
        WaitForSingleObject(ReadThread, 1000);
        CloseHandle(ReadThread);
        ReadThread = NULL;
    }

    // 关闭管道
    if (PipeHandle != NULL)
    {
        DisconnectNamedPipe(PipeHandle); // 断开管道连接
        CloseHandle(PipeHandle);
        PipeHandle = NULL;
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
    std::vector<std::wstring> args;
    for (int i = 0; i < argc; i++)
    {
        std::wstring argTemp = AnsiToUtf16(argv[i]);
        args.push_back(argTemp);
        std::wcout << "argv[" << i << "]:" << argTemp << std::endl;
    }
    if (argc < 3)
    {
        system("pause");
        return 1;
    }
    std::wstring quickLoginQQ = L"";
    if (argc == 4)
    {
        quickLoginQQ = args[3];
    }
    std::wstring bootCommand = createBootCommand(args[1], quickLoginQQ);
    std::wcout << L"Boot Command:" << bootCommand << std::endl;
    CreateSuspendedProcessW(bootCommand.c_str(), args[2].c_str());
    return 0;
}
