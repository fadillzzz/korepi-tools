#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MinHook.h"
#include "Sig.hpp"
#include <format>
#include <inttypes.h>
#include <iostream>

char *base = nullptr;
const auto expectedRegion = 0x3d3000;

void initWrapper() {
    const void *init = Sig::find(base, expectedRegion,
                                 "48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 4C 89 74 24 20 55 48 8D AC 24 10");

    CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)init, nullptr, 0, nullptr);
    ExitThread(0);
}

void start() {
    MH_Initialize();

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

    Sleep(4000);

    MEMORY_BASIC_INFORMATION mbi;
    bool foundBase = false;

    while (foundBase == false) {
        base = nullptr;
        while (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
            if (mbi.RegionSize == expectedRegion) {
                foundBase = true;
                break;
            }

            base += mbi.RegionSize;
        }
    }

    {
        const void *found = Sig::find(base, expectedRegion, "83 3D ? ? ? ? 00 75 04 33 C9 CD 29");

        if (found != nullptr) {
            const auto relative = *(int32_t *)((uintptr_t)found + 2);
            int32_t *role = (int32_t *)((uintptr_t)found + relative + 7);
            *role = 31;
        }
    }

    {
        const void *found =
            Sig::find(base, expectedRegion, "48 89 5C 24 ? 48 89 7C 24 ? 55 48 8D 6C 24 ? 48 81 EC C0 00 00 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)initWrapper, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }
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