#include <windows.h>
#include <iostream>
#include <csignal>
#include <signal.h>
#include <fstream>
HANDLE MainProcessHandle = NULL;
// 快速创建命令
std::wstring env;

bool addEnv(std::wstring key, std::wstring value)
{
    // std::wcout << L"Add Env: " << key << L"=" << value << std::endl;
    if (key.length() == 0 || value.length() == 0)
    {
        return false;
    }
    env += key;
    env += L"=";
    env += value;
    env.append(1, L'\0');
    return true;
}
bool initEnv()
{
    // 循环遍历当前所有环境变量 并调用addEnv添加
    LPWCH envStrings = GetEnvironmentStringsW();
    if (envStrings == NULL)
    {
        return false;
    }

    LPWCH envVar = envStrings;
    while (*envVar)
    {
        std::wstring envEntry(envVar);
        size_t pos = envEntry.find(L'=');
        if (pos != std::wstring::npos)
        {
            std::wstring key = envEntry.substr(0, pos);
            std::wstring value = envEntry.substr(pos + 1);
            addEnv(key, value);
        }
        envVar += envEntry.length() + 1;
    }

    FreeEnvironmentStringsW(envStrings);
    return true;
}
std::string createBootCommand(std::string processName, std::string qucikLogin)
{
    const char *processNameInternal = processName.c_str();
    const char *commandLine = "--enable-logging";
    std::string realProcessName = processNameInternal;
    realProcessName += " ";
    realProcessName += commandLine;
    if (qucikLogin.length() > 0)
    {
        realProcessName += " -q ";
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
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    env.append(1, L'\0');
    // ACSPORT

    std::wcout << L"Process Path: " << GetEnvironmentStringsW() << std::endl;
    if (!CreateProcessW(NULL, (LPWSTR)processName, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, (LPVOID)env.c_str(), NULL, &si, &pi))
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
    // 注入 DLL
    LPVOID pRemoteBuf = VirtualAllocEx(pi.hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, pRemoteBuf, (LPVOID)dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, pRemoteBuf, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    // 恢复进程
    ResumeThread(pi.hThread);
    // 等待进程结束
    WaitForSingleObject(pi.hProcess, INFINITE);

    // 关闭句柄
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    // 判断进程是否残留
    if (WaitForSingleObject(pi.hProcess, 0) == WAIT_TIMEOUT)
    {
        TerminateProcess(pi.hProcess, 0);
    }
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
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    //  创建并挂起进程
    if (!CreateProcessA(NULL, (LPSTR)processName, NULL, NULL, TRUE, CREATE_SUSPENDED, (LPVOID)NULL, NULL, &si, &pi))
    {
        // 输出错误信息
        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPSTR)&errorMsg,
            0,
            NULL);
        std::cerr << "Error: " << (char *)errorMsg << std::endl;
        LocalFree(errorMsg);
        std::cerr << "Failed to start process." << std::endl;
        return;
    }
    MainProcessHandle = pi.hProcess;
    std::cout << "[NapCat Backend] Main Process ID:" << pi.dwProcessId << std::endl;
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
    if (MainProcessHandle != NULL)
    {
        std::cout << "[NapCat Backend] Terminate Main Process." << std::endl;
        TerminateProcess(MainProcessHandle, 0);
    }
    exit(signum);
}
std::tuple<bool, std::string> getQQInstalled()
{
    // 读取注册表 HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\QQ
    LONG QQUnInstallTableResult;
    LONG QQUnInstallResult;
    HKEY QQUnInstallData;
    std::string QQPath;
    char szUninstallString[1024]; // 缓存区1024
    DWORD dwSize = sizeof(szUninstallString);
    QQUnInstallTableResult = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\QQ", 0, KEY_READ, &QQUnInstallData);
    if (QQUnInstallTableResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, "");
    }
    QQUnInstallResult = RegQueryValueEx(QQUnInstallData, "UninstallString", NULL, NULL, (LPBYTE)szUninstallString, &dwSize);
    if (QQUnInstallResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, "");
    }
    QQPath = szUninstallString;
    QQPath = QQPath.substr(0, QQPath.find_last_of("\\")); // 截取路径
    QQPath += "\\QQ.exe";
    return std::make_tuple(true, QQPath);
}
std::tuple<bool, std::wstring> getQQInstalledW()
{
    // 读取注册表 HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\QQ
    LONG QQUnInstallTableResult;
    LONG QQUnInstallResult;
    HKEY QQUnInstallData;
    std::wstring QQPath;
    wchar_t szUninstallString[1024]; // 缓存区1024
    DWORD dwSize = sizeof(szUninstallString);
    QQUnInstallTableResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\QQ", 0, KEY_READ, &QQUnInstallData);
    if (QQUnInstallTableResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, L"");
    }
    QQUnInstallResult = RegQueryValueExW(QQUnInstallData, L"UninstallString", NULL, NULL, (LPBYTE)szUninstallString, &dwSize);
    if (QQUnInstallResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, L"");
    }
    QQPath = szUninstallString;
    QQPath = QQPath.substr(0, QQPath.find_last_of(L"\\")); // 截取路径
    QQPath += L"\\QQ.exe";
    return std::make_tuple(true, QQPath);
}

// Windows下的主函数
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    initEnv();
    // 判断当前是否为管理员权限
    if (!IsUserAnAdmin())
    {
        // 重启并提升权限
        char szPath[MAX_PATH];
        if (GetModuleFileNameA(NULL, szPath, MAX_PATH))
        {
            SHELLEXECUTEINFOA sei = {sizeof(sei)};
            sei.lpVerb = "runas";
            sei.lpFile = szPath;
            sei.lpParameters = GetCommandLineA();
            sei.hwnd = NULL;
            sei.nShow = SW_NORMAL;
            if (!ShellExecuteExA(&sei))
            {
                DWORD error = GetLastError();
                LPVOID errorMsg;
                FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    error,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPSTR)&errorMsg,
                    0,
                    NULL);
                std::cerr << "Error: " << (char *)errorMsg << std::endl;
                LocalFree(errorMsg);
                std::cerr << "Failed to elevate permissions." << std::endl;
                return 1;
            }
            return 0;
        }
    }
    // 设置控制台编码
    system("chcp 65001");
    // 获取QQ安装路径
    std::wstring QQPath;
    bool QQInstalled;
    std::tie(QQInstalled, QQPath) = getQQInstalledW();
    if (!QQInstalled)
    {
        MessageBoxW(NULL, L"请先安装QQ", L"错误", MB_ICONERROR);
        return 1;
    }
    // 查看当前目录是否含有名为LL或者名为LiteLoader文件夹 找到并保存其绝对路径 宽字符
    WIN32_FIND_DATAW FindFileData;
    HANDLE hFind = FindFirstFileW(L"LL", &FindFileData);
    if (hFind == INVALID_HANDLE_VALUE)
    {
        hFind = FindFirstFileW(L"LiteLoader", &FindFileData);
        if (hFind == INVALID_HANDLE_VALUE)
        {
            MessageBoxW(NULL, L"请将LL或LiteLoader文件夹放置在当前目录", L"错误", MB_ICONERROR);
            return 1;
        }
    }
    std::wstring LLPath = FindFileData.cFileName;
    // 获取其绝对路径
    wchar_t szFullPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, szFullPath);
    LLPath = szFullPath;
    LLPath += L"\\";
    LLPath += FindFileData.cFileName;
    // 输出路径
    std::wcout << L"LLPath:" << LLPath << std::endl;
    // 设置环境变量 LAUNCHER_PACKAGE_PATCH
    std::wstring QQFuckPackage = szFullPath;
    QQFuckPackage += L"\\";
    QQFuckPackage += L"qqnt.json";
    addEnv(L"LAUNCHER_PACKAGE_PATCH", QQFuckPackage.c_str());
    // 设置 LAUNCHER_PATCH_PACKAGE_ONCE 设置为1
    addEnv(L"LAUNCHER_PATCH_PACKAGE_ONCE", L"1");
    // 设置 LAUNCHER_PATCH_PACKAGE_HACK_MAIN 设置\LiteLoader_Launcher.js
    addEnv(L"LAUNCHER_PATCH_PACKAGE_HACK_MAIN", L"\\LiteLoader_Launcher.js");
    // 设置 LAUNCHER_PATCH_PACKAGE_REAL_MAIN
    std::wstring realMainPath = szFullPath;
    realMainPath += L"\\";
    realMainPath += L"LiteLoader_Launcher.js";
    addEnv(L"LAUNCHER_PATCH_PACKAGE_REAL_MAIN", realMainPath.c_str());
    std::wstring LLLoadPath = szFullPath;
    LLLoadPath += L"\\";
    LLLoadPath += L"LL\\src\\init.js";
    std::wstring doubleBackslashesPath = LLLoadPath;
    size_t pos = 0;
    while ((pos = doubleBackslashesPath.find(L"\\", pos)) != std::wstring::npos)
    {
        doubleBackslashesPath.replace(pos, 1, L"\\\\");
        pos += 2;
    }
    std::wcout << L"Real Main Path with double backslashes: " << doubleBackslashesPath << std::endl;
    // 写出require('doubleBackslashesPath')文件到realMainPath目录
    std::wofstream outFile(realMainPath);
    if (outFile.is_open())
    {
        outFile << L"require('" << doubleBackslashesPath << L"');" << std::endl;
        // outFile << L"require('./application/app_launcher/index.js');" << std::endl;
        outFile.close();
        std::wcout << L"File written successfully to " << realMainPath << std::endl;
    }
    else
    {
        std::wcerr << L"Failed to open file " << realMainPath << std::endl;
    }
    std::wstring QQInjectDll = szFullPath;
    QQInjectDll += L"\\";
    QQInjectDll += L"NapCatWinBootHook.dll";
    std::wcout << L"NapCatWinBootHook.dll Path:" << QQInjectDll << std::endl;
    // 创建挂起进程
    CreateSuspendedProcessW(QQPath.c_str(), QQInjectDll.c_str());
    return 0;
}