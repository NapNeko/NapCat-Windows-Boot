#include <windows.h>
#include <iostream>
#include <csignal>
#include <signal.h>
#include <fstream>
#include <algorithm>
#include <tuple>

HANDLE MainProcessHandle = NULL;
std::wstring env;

bool addEnv(const std::wstring& key, const std::wstring& value)
{
    if (key.empty() || value.empty())
    {
        return false;
    }
    env += key + L"=" + value + L'\0';
    return true;
}

std::string Utf16ToUtf8(const std::wstring& utf16)
{
    int length = WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, NULL, 0, NULL, NULL);
    std::string utf8(length, 0);
    WideCharToMultiByte(CP_UTF8, 0, utf16.c_str(), -1, &utf8[0], length, NULL, NULL);
    utf8.pop_back();
    return utf8;
}

std::wstring Utf8ToUtf16(const std::string& utf8)
{
    int length = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, NULL, 0);
    std::wstring utf16(length, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &utf16[0], length);
    utf16.pop_back();
    return utf16;
}

bool initEnv()
{
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

void CreateSuspendedProcessW(const wchar_t* processName, const wchar_t* dllPath)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
    env.append(1, L'\0');

    if (!CreateProcessW(NULL, (LPWSTR)processName, NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, (LPVOID)env.c_str(), NULL, &si, &pi))
    {
        DWORD error = GetLastError();
        LPVOID errorMsg;
        FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, error, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&errorMsg, 0, NULL);
        std::wcerr << L"Error Code: " << error << std::endl;
        std::wcerr << L"Process Path: " << processName << std::endl;
        std::wcerr << L"Error: " << (wchar_t*)errorMsg << std::endl;
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

std::tuple<bool, std::wstring> getQQInstalledW()
{
    HKEY QQUnInstallData;
    std::wstring QQPath;
    wchar_t szUninstallString[1024];
    DWORD dwSize = sizeof(szUninstallString);
    LONG QQUnInstallTableResult = RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\QQ", 0, KEY_READ, &QQUnInstallData);
    if (QQUnInstallTableResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, L"");
    }
    LONG QQUnInstallResult = RegQueryValueExW(QQUnInstallData, L"UninstallString", NULL, NULL, (LPBYTE)szUninstallString, &dwSize);
    if (QQUnInstallResult != ERROR_SUCCESS)
    {
        return std::make_tuple(false, L"");
    }
    QQPath = szUninstallString;
    QQPath = QQPath.substr(0, QQPath.find_last_of(L"\\")) + L"\\QQ.exe";
    return std::make_tuple(true, QQPath);
}

std::wstring getFullPath(const std::wstring& relativePath)
{
    wchar_t szFullPath[MAX_PATH];
    GetCurrentDirectoryW(MAX_PATH, szFullPath);
    std::wstring fullPath = szFullPath;
    fullPath += L"\\" + relativePath;
    return fullPath;
}

void writeScriptToFile(const std::wstring& filePath, const std::wstring& script)
{
    std::ofstream outFile(filePath, std::ios::out | std::ios::binary);
    if (outFile.is_open())
    {
        std::string script_utf8 = Utf16ToUtf8(script);
        outFile.write(script_utf8.c_str(), script_utf8.size());
        outFile.close();
        std::wcout << L"File written successfully to " << filePath << std::endl;
    }
    else
    {
        std::wcerr << L"Failed to open file " << filePath << std::endl;
    }
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    initEnv();
    system("chcp 65001");

    auto [QQInstalled, QQPath] = getQQInstalledW();
    if (!QQInstalled)
    {
        MessageBoxW(NULL, L"请先安装QQ", L"错误", MB_ICONERROR);
        return 1;
    }

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

    std::wstring LLPath = getFullPath(FindFileData.cFileName);
    std::wcout << L"LLPath:" << LLPath << std::endl;

    std::wstring QQFuckPackage = getFullPath(L"qqnt.json");
    addEnv(L"LAUNCHER_PACKAGE_PATCH", QQFuckPackage);
    addEnv(L"LAUNCHER_PATCH_PACKAGE_ONCE", L"1");
    addEnv(L"LAUNCHER_PATCH_PACKAGE_HACK_MAIN", L"\\LiteLoader_Launcher.js");

    std::wstring realMainPath = getFullPath(L"LiteLoader_Launcher.js");
    addEnv(L"LAUNCHER_PATCH_PACKAGE_REAL_MAIN", realMainPath);

    std::wstring LLLoadPath = getFullPath(L"LL\\src\\init.js");
    std::replace(LLLoadPath.begin(), LLLoadPath.end(), L'\\', L'/');
    writeScriptToFile(realMainPath, L"require(`" + LLLoadPath + L"`);");

    std::wstring QQInjectDll = getFullPath(L"NapCatWinBootHook.dll");
    std::wcout << L"NapCatWinBootHook.dll Path:" << QQInjectDll << std::endl;

    CreateSuspendedProcessW(QQPath.c_str(), QQInjectDll.c_str());
    return 0;
}