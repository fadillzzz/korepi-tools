#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <TlHelp32.h>
#include <iostream>
#include <shellapi.h>
#include <string>

uintptr_t GetModuleBaseAddress(HANDLE proc, const wchar_t *moduleName) {
    uintptr_t address = 0;

    HANDLE handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(proc));

    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        MODULEENTRY32 moduleEntry;

        moduleEntry.dwSize = sizeof(moduleEntry);

        while (Module32Next(handleSnapshot, &moduleEntry)) {
            if (_wcsicmp(moduleEntry.szModule, moduleName) == 0) {
                address = (uintptr_t)moduleEntry.modBaseAddr;
                break;
            }
        }
    }

    CloseHandle(handleSnapshot);

    return address;
}

void inject(HANDLE proc, const std::string dll) {
    const auto dllAddr = VirtualAllocEx(proc, nullptr, dll.size(), MEM_COMMIT, PAGE_READWRITE);

    if (!dllAddr) {
        std::cout << "Failed to allocate memory for DLL path" << std::endl;
        return;
    }

    if (!WriteProcessMemory(proc, dllAddr, dll.c_str(), dll.size(), nullptr)) {
        std::cout << "Failed to write DLL path into memory" << std::endl;
        return;
    }

    PTHREAD_START_ROUTINE loadLib = nullptr;

    do {
        const auto kernel32 = GetModuleBaseAddress(proc, L"kernel32.dll");
        loadLib = (PTHREAD_START_ROUTINE)GetProcAddress((HMODULE)kernel32, "LoadLibraryA");
        std::cout << "kernel32.dll hasn't been loaded. Waiting for 1 sec..." << std::endl;
        Sleep(1000);
    } while (loadLib == nullptr);

    const auto thread =
        CreateRemoteThreadEx(proc, nullptr, 0, (PTHREAD_START_ROUTINE)loadLib, dllAddr, 0, nullptr, nullptr);

    if (!thread) {
        std::cout << "Failed to create remote thread" << std::endl;
        return;
    }

    std::cout << "Created remote thread for loading DLL" << std::endl;
}

int main() {
    SHELLEXECUTEINFO shExecInfo = {0};
    shExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
    shExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    shExecInfo.lpFile = L"korepi.exe";
    shExecInfo.lpDirectory = NULL;
    shExecInfo.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteEx(&shExecInfo)) {
        std::cout << "Failed to start korepi.exe" << std::endl;
    } else {
        const std::string dll = "lol.dll";

        inject(shExecInfo.hProcess, dll);

        CloseHandle(shExecInfo.hProcess);
    }

    std::cout << "Press any key to exit" << std::endl;
    getchar();

    return 0;
}