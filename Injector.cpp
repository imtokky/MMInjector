#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

// ターゲットプロセスとやり取りする構造体
struct MANUAL_MAPPING_DATA {
    using f_LoadLibraryA = HMODULE(WINAPI*)(LPCSTR);
    using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE, LPCSTR);
    using f_RtlAddFunctionTable = BOOLEAN(WINAPI*)(PRUNTIME_FUNCTION, DWORD, DWORD64); // x64用

    f_LoadLibraryA pLoadLibraryA;
    f_GetProcAddress pGetProcAddress;
    f_RtlAddFunctionTable pRtlAddFunctionTable;
    PBYTE pModuleBase;              // ターゲットプロセス上のDLLベースアドレス
    DWORD Status;                   // 結果ステータス (0:未完了, 0x404040:失敗, その他:成功)
    DWORD Reserved1;
    DWORD Reserved2;
    DWORD Reserved3;
};

// この関数はターゲットプロセス内で実行されます
// 引数 a1: MANUAL_MAPPING_DATA 構造体へのポインタ
DWORD __stdcall PELoaderShellcode(MANUAL_MAPPING_DATA* pData);


// 注意: この関数内では外部関数（printfなど）やグローバル変数を一切使ってはいけません。
// すべて pData 経由で取得した関数ポインタを使用する必要があります。
#pragma runtime_checks( "", off )
#pragma optimize( "", off )

DWORD __stdcall PELoaderShellcode(MANUAL_MAPPING_DATA* pData)
{
    if (!pData) {
        return 0;
    }

    PBYTE pBase = pData->pModuleBase;
    auto* pDosHeader = (PIMAGE_DOS_HEADER)pBase;
    auto* pNtHeaders = (PIMAGE_NT_HEADERS)(pBase + pDosHeader->e_lfanew);
    auto* pOpt = &pNtHeaders->OptionalHeader;

    auto _LoadLibraryA = pData->pLoadLibraryA;
    auto _GetProcAddress = pData->pGetProcAddress;
    auto _DllMain = (BOOL(WINAPI*)(HMODULE, DWORD, LPVOID))(pBase + pOpt->AddressOfEntryPoint);
    auto _RtlAddFunctionTable = pData->pRtlAddFunctionTable;

    // --- 1. リロケーション ---
    INT_PTR LocationDelta = (INT_PTR)pBase - (INT_PTR)pOpt->ImageBase;

    if (LocationDelta && pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
        auto* pRelocData = (PIMAGE_BASE_RELOCATION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        while (pRelocData->VirtualAddress) {
            UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = (WORD*)(pRelocData + 1);

            for (UINT i = 0; i < AmountOfEntries; ++i, ++pRelativeInfo) {
                if (RELOC_FLAG(*pRelativeInfo)) {
                    UINT_PTR* pPatch = (UINT_PTR*)(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
                    *pPatch += (UINT_PTR)LocationDelta;  // UINT_PTRにキャスト
                }
            }
            pRelocData = (PIMAGE_BASE_RELOCATION)((BYTE*)pRelocData + pRelocData->SizeOfBlock);
        }
    }

    // --- 2. インポート解決 ---
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto* pImportDescr = (PIMAGE_IMPORT_DESCRIPTOR)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (pImportDescr->Name) {
            char* szMod = (char*)(pBase + pImportDescr->Name);
            HINSTANCE hDll = _LoadLibraryA(szMod);

            ULONG_PTR* pThunkRef = (ULONG_PTR*)(pBase + pImportDescr->OriginalFirstThunk);
            ULONG_PTR* pFuncRef = (ULONG_PTR*)(pBase + pImportDescr->FirstThunk);

            if (!pThunkRef) pThunkRef = pFuncRef;

            for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                    // Ordinal by number
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, (LPCSTR)(*pThunkRef & 0xFFFF));
                }
                else {
                    // Import by name
                    auto* pImport = (PIMAGE_IMPORT_BY_NAME)(pBase + (*pThunkRef));
                    *pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
                }
            }
            ++pImportDescr;
        }
    }

    // --- 3. TLS コールバック ---
    if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
        auto* pTLS = (PIMAGE_TLS_DIRECTORY)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        auto* pCallback = (PIMAGE_TLS_CALLBACK*)(pTLS->AddressOfCallBacks);

        for (; pCallback && *pCallback; ++pCallback) {
            (*pCallback)((LPVOID)pBase, DLL_PROCESS_ATTACH, nullptr);
        }
    }

    // --- 4. 例外ハンドラ登録 (x64) ---
    bool ehResult = false;
    if (_RtlAddFunctionTable && pData->Reserved1) {
        if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size) {
            ehResult = _RtlAddFunctionTable(
                (PRUNTIME_FUNCTION)(pBase + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress),
                pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(RUNTIME_FUNCTION),
                (DWORD64)pBase
            );
        }
    }

    // --- 5. DllMain 呼び出し ---
    _DllMain((HMODULE)pBase, DLL_PROCESS_ATTACH, nullptr);

    // ステータス設定
    if (ehResult) {
        pData->Status = 0x505050;  // エラー
    }
    else {
        pData->Status = (DWORD)(UINT_PTR)pBase;  // 成功
    }

    return (DWORD)(UINT_PTR)pBase;
}

void __stdcall PELoaderShellcodeEnd() {}

#pragma optimize( "", on )
#pragma runtime_checks( "", restore )

bool ManualMapInject(HANDLE hProcess, char* pDllData) {
    auto* pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(pDllData);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto* pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(pDllData + pDosHeader->e_lfanew);
    if (pNtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;

    // 1. ターゲットプロセスにメモリ確保（最初はRWアクセス）
    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(
        hProcess, nullptr,
        pNtHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE  // 最初はRWのみ
    ));
    if (!pTargetBase) return false;

    // ヘッダー保護を一時的に変更
    DWORD oldProtect;
    VirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    // 2. ヘッダーコピー
    if (!WriteProcessMemory(hProcess, pTargetBase, pDllData, 0x1000, nullptr)) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    // 3. セクションコピー
    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProcess,
                pTargetBase + pSectionHeader->VirtualAddress,
                pDllData + pSectionHeader->PointerToRawData,
                pSectionHeader->SizeOfRawData, nullptr)) {
                VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    // 4. データ構造体の準備
    MANUAL_MAPPING_DATA data = { 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    data.pRtlAddFunctionTable = (MANUAL_MAPPING_DATA::f_RtlAddFunctionTable)GetProcAddress(hNtdll, "RtlAddFunctionTable");
    data.pModuleBase = pTargetBase;
    data.Status = 0;
    data.Reserved1 = 1;  // RtlAddFunctionTable有効化フラグ

    // 5. データ構造体用メモリ確保と書き込み
    BYTE* pRemoteData = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!pRemoteData) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        return false;
    }
    WriteProcessMemory(hProcess, pRemoteData, &data, sizeof(MANUAL_MAPPING_DATA), nullptr);

    // 6. シェルコードの書き込み
    size_t shellcodeSize = (size_t)PELoaderShellcodeEnd - (size_t)PELoaderShellcode;
    BYTE* pRemoteShellcode = reinterpret_cast<BYTE*>(VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pRemoteShellcode) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        return false;
    }
    WriteProcessMemory(hProcess, pRemoteShellcode, (LPCVOID)PELoaderShellcode, shellcodeSize, nullptr);

    // 7. リモートスレッド実行
    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pRemoteShellcode), pRemoteData, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);

    // 8. 待機ループ
    bool success = false;
    int timeout = 5000; // 5秒タイムアウト
    while (timeout > 0) {
        MANUAL_MAPPING_DATA dataChecked = { 0 };
        ReadProcessMemory(hProcess, pRemoteData, &dataChecked, sizeof(MANUAL_MAPPING_DATA), nullptr);

        if (dataChecked.Status == 0x404040) { // エラー
            break;
        }
        if (dataChecked.Status != 0) { // 成功
            success = true;
            break;
        }

        DWORD exitCode = 0;
        GetExitCodeProcess(hProcess, &exitCode);
        if (exitCode != STILL_ACTIVE) break;

        Sleep(10);
        timeout -= 10;
    }

    // 9. 【重要】各セクションに適切なメモリ保護を設定
    if (success) {
        // .rsrc と .reloc セクションをゼロ埋め（アンチダンプ対策）
        pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
            if (pSectionHeader->SizeOfRawData == 0) continue;

            // セクション名を確認
            char sectionName[9] = { 0 };
            memcpy(sectionName, pSectionHeader->Name, 8);

            if (strcmp(sectionName, ".rsrc") == 0 || strcmp(sectionName, ".reloc") == 0) {
                // リソース/リロケーションセクションをゼロ埋め
                BYTE* emptySection = new BYTE[pSectionHeader->SizeOfRawData]();
                WriteProcessMemory(hProcess, pTargetBase + pSectionHeader->VirtualAddress, emptySection, pSectionHeader->SizeOfRawData, nullptr);
                delete[] emptySection;
            }

            // 各セクションの保護属性を設定
            DWORD protection = PAGE_READONLY;
            if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                protection = (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
            }
            else if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_WRITE) {
                protection = PAGE_READWRITE;
            }

            DWORD oldProt;
            VirtualProtectEx(hProcess, pTargetBase + pSectionHeader->VirtualAddress, pSectionHeader->SizeOfRawData, protection, &oldProt);
        }

        // ヘッダーをREADONLYに変更
        DWORD headerProtect;
        VirtualProtectEx(hProcess, pTargetBase, pNtHeaders->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &headerProtect);

        // ヘッダーをゼロ埋め（証拠隠滅）
        BYTE empty[0x1000] = { 0 };
        WriteProcessMemory(hProcess, pTargetBase, empty, 0x1000, nullptr);
    }

    // 10. クリーンアップ
    VirtualFreeEx(hProcess, pRemoteData, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, pRemoteShellcode, 0, MEM_RELEASE);

    if (success) {
        BYTE corruptedStub[0x40] = { 0 };
        WriteProcessMemory(hProcess, pTargetBase + 0x40, corruptedStub, sizeof(corruptedStub), nullptr);

        WORD invalidSignature = 0x0000;
        WriteProcessMemory(hProcess, pTargetBase, &invalidSignature, sizeof(WORD), nullptr);
    }
    return success;
}