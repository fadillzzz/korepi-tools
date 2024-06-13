#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <format>
#include <iostream>

#include "MinHook.h"
#include "Sig.hpp"

typedef uintptr_t (*hwid_t)(uintptr_t, size_t, size_t, uintptr_t);
hwid_t oHwid = nullptr;

uintptr_t hwid(uintptr_t a1, size_t a2, size_t a3, uintptr_t a4) {
    if (a1 == 0x14ecf0) {
        const auto s = std::string("---------Hi-Korepi-Devs---------");
        memcpy((void *)a4, s.c_str(), s.size() + 1);
    }

    return oHwid(a1, a2, a3, a4);
}

bool fakeResp = false;

typedef void (*options_t)(void *, size_t, void *);
options_t oOptions = nullptr;

void options(void *a1, size_t a2, void *a3) {
    if (a2 == 10002) {
        if (memcmp(a3, "https://md5c.", 13) == 0) {
            fakeResp = true;
        }
    }

    oOptions(a1, a2, a3);
}

typedef size_t (*respHandler_t)(void *, char *, size_t, uint64_t *, uint32_t *a5);
respHandler_t oRespHandler = nullptr;

const auto resp =
    R"({"msg": "vpJSftgQ2noDAZR3Iri/ForvdhDZvxwlJCXowV9TgKSs+BoMyBMOIuxjpDcMTSov1thaXhg/d9aAKcpxOP6glQ3bSd8bHIGMku3Ck/33VdYhtzx4HwC4Lel5mVGZ9+2jffsIgHyIwxMl+8kYwh/QGQRlkC8zFfyNaMszsZiOxIJCy/RMYfI3buvCDPH/4D1/VxysPnaX+QtrVrs7Bt74byqnd38bi0GhpllEWL7CO+7fI+vMe2OSv6s0CUaOqzhDC5N8wIkHsthyVyP+GYoltTov3Bu5iaxmgZc/eYQPTkTWQ759pIVNjKJwnQI3EtOEdrRog6LAkA/CMGwMwBkScvY508Z3KhnNqqIIF9RpYLI6rdST+o2t5gIK4sElQg/2wHZT6wSm23t7YdxnwzEFZysv/H0y63iI4NMUmyZIkRvCyxlWVMpTt/rV9qubdbCjGDxG7A/0LbxCJBfBgEWu4Krpp1S+hk4qgIB+2apCh5sxU76mLzQdFLzNrgmbQADapyDO6rWw777F9FKlo/r9II8kISi/+2FxXp7TZE3ALbcyUo7zKucahsq7u9ucENm64D3PKV4YZCHchQY7xyYI4DaC1PQzleJxGaGbCoBQ0PZK7f33d3N3qB10OaEfe2de4uTcOKbVAjtjSLrlZcMGiZd40Bho76xCtcgAKG2FDxbH/PJo4BoIYwqiDzqpmxXBOsn0JqKLGLaAyU840GAgyLO62lE7/A26w+B9q7hkOIcKlfXZpdwjsll/dADe2U/uF5nrLxEOUGDx9gbUoB95KLD1S3KCCyaLuv8j4imt2E9EgDzk/1XdIwnbPGAECajV5z4yTpMuyD9XBhmJQIFutw==", "code": 200})";
const auto chunkLength = std::format("{:x}", strlen(resp));
const auto firstChunk = std::format("{}\r\n{}\r\n", chunkLength, resp);
const auto secondChunk = std::format("0\r\n\r\n");
const auto aggregated = firstChunk + secondChunk;

size_t respHandler(void *a1, char *content, size_t length, uint64_t *a4, uint32_t *a5) {
    if (fakeResp == true) {
        fakeResp = false;
        memcpy(content, aggregated.c_str(), aggregated.size() + 1);
        length = aggregated.size();
    }

    return oRespHandler(a1, content, length, a4, a5);
}

typedef HANDLE(WINAPI *CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID,
                                               DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
CreateRemoteThreadEx_t oCreateRemoteThreadEx = nullptr;

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

    const auto loadLib = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    const auto thread =
        oCreateRemoteThreadEx(proc, nullptr, 0, (PTHREAD_START_ROUTINE)loadLib, dllAddr, 0, nullptr, nullptr);

    if (!thread) {
        std::cout << "Failed to create remote thread" << std::endl;
        return;
    }

    std::cout << "Created remote thread for loading DLL" << std::endl;
}

HANDLE WINAPI createThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                           LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                           LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    // if ((int64_t)hProcess != -1) {
    //     const auto path = std::filesystem::current_path() / "dll.dll";
    //     inject(hProcess, path.string());
    //     Sleep(2000);
    // }

    return oCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                 dwCreationFlags, lpAttributeList, lpThreadId);
}

void start() {
    const auto ntdll = GetModuleHandle(L"ntdll.dll");
    uint8_t callcode = ((uint8_t *)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
    uint8_t restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};

    volatile auto ntProtectVirtualMemory = (uint8_t *)GetProcAddress(ntdll, "NtProtectVirtualMemory");

    while (true) {
        if (ntProtectVirtualMemory[0] != 0x4C) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect);
            memcpy(ntProtectVirtualMemory, restore, sizeof(restore));
            VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), oldProtect, nullptr);

            break;
        }
    }

    MH_Initialize();

    const auto exe = GetModuleHandle(nullptr);
    const auto header = (PIMAGE_DOS_HEADER)exe;
    const auto nt = (PIMAGE_NT_HEADERS)((uint8_t *)exe + header->e_lfanew);
    const auto size = nt->OptionalHeader.SizeOfImage;

    {
        const void *found = Sig::find(
            exe, size,
            "40 53 56 41 56 41 57 48 83 EC 28 48 BB FF FF FF FF FF FF FF 7F 4D 8B F9 4C 8B F2 48 8B F1 48 3B D3");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, hwid, (LPVOID *)&oHwid);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found = Sig::find(exe, size, "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, options, (LPVOID *)&oOptions);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found = Sig::find(exe, size, "48 89 5C 24 20 56 57 41 54 41 55 41 56 48 83 EC 20");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, respHandler, (LPVOID *)&oRespHandler);
            MH_EnableHook((LPVOID)found);
        }
    }

    // {
    //     const auto remoteThreadEx = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateRemoteThreadEx");
    //     MH_CreateHook((LPVOID)remoteThreadEx, (LPVOID)createThread, (LPVOID *)&oCreateRemoteThreadEx);
    //     MH_EnableHook((LPVOID)remoteThreadEx);
    // }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        const auto thread = CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)start, nullptr, 0, nullptr);
        DisableThreadLibraryCalls(hinstDLL);
        if (thread) {
            CloseHandle(thread);
        }
    }

    return true;
}