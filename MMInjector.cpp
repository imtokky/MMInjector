#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>
#include "Injector.h"

using namespace std;
using json = nlohmann::json;


static string DecryptXOR(const char* encrypted, size_t len) {
    string result;
    result.reserve(len);
    for (size_t i = 0; i < len; i++) {
        result += (encrypted[i] ^ 0x10);
    }
    return result;
}

bool ManualMapInject(HANDLE hProcess, char* pBuffer);
bool CheckArchitecture(HANDLE hProcess);

static void PrintConsole(const string& msg) {
    cout << msg << endl;
}

int main(int argc, const char** argv)
{
    // 管理者権限のチェック
    BOOL isMember = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup = nullptr;

    if (AllocateAndInitializeSid(&ntAuthority, 2,
        SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isMember);
        FreeSid(adminGroup);
    }

    if (!isMember)
    {
        PrintConsole("This program must be run as administrator");
        system("PAUSE");
        return -1;
    }

    // jsonパース
    ifstream f("settings.json");
    if (!f.is_open()) {
        PrintConsole("[Error] settings.json could not be opened.");
        PrintConsole("Make sure 'settings.json' is in the same directory as the executable.");
        system("PAUSE");
        return -1;
    }

    json settings;
    try {
        settings = json::parse(f);
    }
    catch (json::parse_error& e) {
        PrintConsole("[Error] Failed to parse settings.json");
        PrintConsole("Details: " + string(e.what()));
        system("PAUSE");
        return -1;
    }

    string dllName = "\\" + string(settings["dllName"]);
    string fullpath = settings["targetFullPath"];

    // DLLパスの構築
    string currentPath = argv[0];
    size_t lastSlash = currentPath.find_last_of("\\");
    string baseDir = (lastSlash != string::npos) ? currentPath.substr(0, lastSlash) : ".";
    string dllPath = baseDir + dllName;

    // ターゲットプロセス名の抽出
    size_t filename_i = fullpath.find_last_of("\\");
    string targetProcessName;

    if (filename_i != string::npos) {
        targetProcessName = fullpath.substr(filename_i + 1);
    }
    else {
        targetProcessName = fullpath;
    }

    PrintConsole("Target process: " + targetProcessName);

    DWORD targetPID = 0;
    HANDLE hProcess = nullptr;
    HANDLE hMainThread = nullptr;
    bool bCreatedProcess = false;

    // ターゲットプロセスの検索/起動
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe32{};
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (_stricmp(pe32.szExeFile, targetProcessName.c_str()) == 0) {
                    targetPID = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        CloseHandle(hSnapshot);
    }

    // プロセスのオープン or 起動
    if (targetPID != 0) {
        PrintConsole("The process is open. Please close it.");
        system("PAUSE");
        return -1;
    }
    else {
        PrintConsole("Launching in suspended mode...");

        STARTUPINFOA si = { sizeof(si) };
        PROCESS_INFORMATION pi = { 0 };

        if (CreateProcessA(fullpath.c_str(), NULL, NULL, NULL, FALSE,
            CREATE_SUSPENDED, NULL, baseDir.c_str(), &si, &pi)) {
            hProcess = pi.hProcess;
            hMainThread = pi.hThread;
            targetPID = pi.dwProcessId;
            bCreatedProcess = true;
            PrintConsole("Process launched (PID: " + to_string(targetPID) + ")");
        }
        else {
            PrintConsole("Failed to launch process. Error: " + to_string(GetLastError()));
            system("PAUSE");
            return -1;
        }
    }

    // SeDebugPrivilege取得
    HANDLE hToken;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        LUID luid;
        if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
            TOKEN_PRIVILEGES tp = {};
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        }
        CloseHandle(hToken);
    }

    // アーキテクチャチェック
    if (!CheckArchitecture(hProcess)) {
        PrintConsole("Architecture mismatch (32-bit vs 64-bit).");
        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -3;
    }

    // DLL存在確認
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        PrintConsole("DLL file not found: " + dllPath);
        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -4;
    }

    // ランダムファイル名でコピー
    srand(static_cast<unsigned int>(GetTickCount64()));
    string randomFileName = to_string(rand()) + ".tmp";
    string randomFilePath = baseDir + "\\" + randomFileName;

    if (!CopyFileA(dllPath.c_str(), randomFilePath.c_str(), FALSE)) {
        PrintConsole("Failed to copy DLL. Error: " + to_string(GetLastError()));
        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -5;
    }

    // ファイル読み込み
    ifstream file(randomFilePath, ios::binary | ios::ate);
    if (file.fail()) {
        PrintConsole("Failed to open copied DLL.");
        DeleteFileA(randomFilePath.c_str());
        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -5;
    }

    streamsize fileSize = file.tellg();
    if (fileSize < 4096) {
        PrintConsole("File too small (minimum 4KB required).");
        file.close();
        DeleteFileA(randomFilePath.c_str());
        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -6;
    }

    char* pInjectedPE = new char[fileSize];
    file.seekg(0, ios::beg);
    file.read(pInjectedPE, fileSize);
    file.close();

    // 一時ファイルを削除
    DeleteFileA(randomFilePath.c_str());

    // Manual Map インジェクション
    PrintConsole("Starting manual map injection...");
    bool success = ManualMapInject(hProcess, pInjectedPE);
    delete[] pInjectedPE;

    if (success) {
        PrintConsole("Injection successful!");

        // 停止状態で起動した場合はスレッドを再開
        if (bCreatedProcess && hMainThread) {
            PrintConsole("Resuming main thread...");
            if (ResumeThread(hMainThread) == (DWORD)-1) {
                DWORD err = GetLastError();
                PrintConsole("Failed to resume thread. Error: " + to_string(err));
                TerminateProcess(hProcess, 1);
                CloseHandle(hMainThread);
                CloseHandle(hProcess);
                system("PAUSE");
                return -9;
            }
            CloseHandle(hMainThread);
        }

        CloseHandle(hProcess);
        PrintConsole("\nInjection completed successfully\n");
        Sleep(3000);
        return 0;
    }
    else {
        // 失敗時、デバッグ情報を取得
        PrintConsole("\nInjection Failed - Diagnostic Information");

        // 最後のエラーコードを取得
        DWORD lastError = GetLastError();
        if (lastError != 0) {
            char hexStr[32];
            sprintf_s(hexStr, "0x%08X", lastError);
            PrintConsole("Last Win32 Error: " + to_string(lastError) + " (" + hexStr + ")");

            // エラーメッセージを取得
            LPSTR messageBuffer = nullptr;
            DWORD result = FormatMessageA(
                FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                NULL,
                lastError,
                MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                (LPSTR)&messageBuffer,
                0,
                NULL
            );

            if (result && messageBuffer) {
                string errMsg = messageBuffer;
                // 改行を削除
                errMsg.erase(remove(errMsg.begin(), errMsg.end(), '\r'), errMsg.end());
                errMsg.erase(remove(errMsg.begin(), errMsg.end(), '\n'), errMsg.end());
                PrintConsole("Error Description: " + errMsg);
                LocalFree(messageBuffer);
            }
        }
        else {
            PrintConsole("No Win32 error recorded");
        }

        // プロセスの終了コードを確認
        DWORD exitCode = 0;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            if (exitCode != STILL_ACTIVE) {
                char hexStr[32];
                sprintf_s(hexStr, "0x%08X", exitCode);
                PrintConsole("Target process terminated with exit code: " + to_string(exitCode) + " (" + hexStr + ")");
            }
            else {
                PrintConsole("Target process is still running");
            }
        }

        // スレッドの終了コードを確認（プロセス起動時のみ）
        if (bCreatedProcess && hMainThread) {
            DWORD threadExitCode = 0;
            if (GetExitCodeThread(hMainThread, &threadExitCode)) {
                if (threadExitCode != STILL_ACTIVE) {
                    char hexStr[32];
                    sprintf_s(hexStr, "0x%08X", threadExitCode);
                    PrintConsole("Main thread exit code: " + to_string(threadExitCode) + " (" + hexStr + ")");
                }
                else {
                    PrintConsole("Main thread is still active");
                }
            }
        }

        PrintConsole("End of Diagnostic Information\n");
        PrintConsole("Injection failed. Please check the diagnostic information above.");

        if (bCreatedProcess) {
            TerminateProcess(hProcess, 1);
        }
        if (hMainThread) CloseHandle(hMainThread);
        CloseHandle(hProcess);
        system("PAUSE");
        return -8;
    }
}

bool CheckArchitecture(HANDLE hProcess)
{
    BOOL bTargetWow64 = FALSE;
    BOOL bCurrentWow64 = FALSE;

    if (!IsWow64Process(hProcess, &bTargetWow64)) {
        return false;
    }

    IsWow64Process(GetCurrentProcess(), &bCurrentWow64);
    return (bTargetWow64 == bCurrentWow64);
}