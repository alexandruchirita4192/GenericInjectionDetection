#ifndef WINDOWS_INJECTION_DETECTOR_H
#define WINDOWS_INJECTION_DETECTOR_H

#include "injection_detector.h"
#include "injection_dependency.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <wintrust.h>   // For WinVerifyTrust function and structures
#include <softpub.h>    // For WINTRUST_ACTION_GENERIC_VERIFY_V2
#include <tchar.h>      // For _TCHAR definitions
#include <string>

// Utility function to convert char[] to std::wstring
std::wstring charArrayToWstring(const char* charArray) {
    std::wstring wstr(charArray, charArray + strlen(charArray));
    return wstr;
}

class WindowsInjectionDetector : public InjectionDetector {
public:
    // Verifies if the DLL has a valid digital signature
    bool VerifySignature(const std::wstring& filePath) {
        WINTRUST_FILE_INFO fileInfo = { 0 };
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath.c_str();

        GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        WINTRUST_DATA trustData = { 0 };
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;  // Don't display any UI
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;

        LONG status = WinVerifyTrust(NULL, &actionGUID, &trustData);

        if (status == ERROR_SUCCESS) {
            std::wcout << L"Valid signature for: " << filePath << std::endl;
            return true;
        } else {
            std::wcerr << L"Invalid or no signature for: " << filePath << std::endl;
            return false;
        }
    }

    // Enumerates all loaded modules (DLLs) and checks their signatures
    void DetectModuleInjection() override {
        DWORD pid = GetCurrentProcessId();
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);

        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cerr << "Failed to create module snapshot." << std::endl;
            return;
        }

        MODULEENTRY32 moduleEntry;
        moduleEntry.dwSize = sizeof(MODULEENTRY32);

        if (Module32First(hSnapshot, &moduleEntry)) {
            do {
                std::wcout << L"Checking module: " << moduleEntry.szModule << std::endl;

                // Check the signature of each loaded module
                VerifySignature(charArrayToWstring(moduleEntry.szExePath));
            } while (Module32Next(hSnapshot, &moduleEntry));
        }

        CloseHandle(hSnapshot);
    }

    void DetectIATInjection() override {
        HMODULE hModule = GetModuleHandle(NULL); // Handle to the current process

        // Step 1: Get DOS and NT headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
            std::cerr << "Invalid DOS signature" << std::endl;
            return;
        }

        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
            std::cerr << "Invalid NT signature" << std::endl;
            return;
        }

        // Step 2: Locate the IAT using the IMAGE_IMPORT_DESCRIPTOR
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule +
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        while (importDesc->Name) {
            LPCSTR moduleName = (LPCSTR)((BYTE*)hModule + importDesc->Name);
            std::cout << "Checking imports from: " << moduleName << std::endl;

            HMODULE hDll = GetModuleHandleA(moduleName);
            if (!hDll) {
                std::cerr << "Failed to get handle for module: " << moduleName << std::endl;
                importDesc++;
                continue;
            }

            // Step 3: Verify each imported function address
            PIMAGE_THUNK_DATA thunkOrig = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);

            while (thunkOrig->u1.AddressOfData) {
                if (thunkOrig->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal (skipping this for now)
                } else {
                    // Import by name
                    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + thunkOrig->u1.AddressOfData);
                    FARPROC correctProcAddr = GetProcAddress(hDll, (LPCSTR)importByName->Name);

                    if (correctProcAddr != (FARPROC)thunk->u1.Function) {
                        std::cerr << "Potential IAT hijack detected! Function: " << importByName->Name << std::endl;
                        std::cerr << "Original address [" << importByName->Name << "]: " << (FARPROC)thunk->u1.Function << ", Expected address [" << importByName->Name << "]: " << correctProcAddr << std::endl;
                    }
                }
                thunkOrig++;
                thunk++;
            }
            importDesc++;
        }
    }

    // Detects potential FAT (vtable) injection by checking the vtable of an object.
    void DetectFunctionPointerInjection() override {
        // FAT injection detection can be specific to the application structure (like virtual table).
        std::cout << "Checking for FAT injection (function pointer table manipulation)." << std::endl;

        MyClass obj;
        void** vtable = *(void***)&obj;  // Get the vtable of the object
        //FARPROC expectedFuncAddr = (FARPROC)&MyClass::MyFunction;
        void (MyClass::*expectedFunc)() = &MyClass::MyFunction;

        std::cout << "Checking vtable for MyClass object..." << std::endl;

        // Implement virtual table integrity checks here.
        // if ((FARPROC)vtable[0] != expectedFuncAddr) {
        if (*(void**)&expectedFunc != vtable[0]) {
            std::cerr << "Potential vtable hijack detected! Function address in vtable: "
                      //<< vtable[0] << ", Expected address: " << expectedFuncAddr << std::endl;
                      << vtable[0] << ", Expected address: " << *(void**)&expectedFunc << std::endl;
        } else {
            std::cout << "Vtable integrity verified." << std::endl;
        }
    }
};

#endif // WINDOWS_INJECTION_DETECTOR_H
