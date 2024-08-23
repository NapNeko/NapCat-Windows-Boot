#include <windows.h>
#include <iostream>

void StartProcessAndInjectDLL(const char *processName, const char *dllPath)
{
    STARTUPINFOA si = {sizeof(si)};
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    //si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    if (!CreateProcessA(NULL, (LPSTR)processName, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        std::cerr << "Failed to start process." << std::endl;
        return;
    }

    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, strlen(dllPath) + 1, NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);

    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, pRemoteBuf, 0, MEM_RELEASE);

    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    system("pause");
}

int main()
{
    const char *processName = "D:\\AppD\\QQNT\\QQ.exe --enable-logging";
    const char *dllPath = "D:\\AppD\\QQNT\\NapCatWinBootMain.dll";
    StartProcessAndInjectDLL(processName, dllPath);

    return 0;
}