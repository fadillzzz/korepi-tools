#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MinHook.h"
#include "Sig.hpp"
#include <format>
#include <iostream>

bool fakeResp = false;
void *userData;
typedef size_t (*callback_t)(char *ptr, size_t size, size_t nmemb, void *userdata);
callback_t callback = nullptr;

typedef void (*options_t)(void *, size_t, void *);
options_t oOptions = nullptr;

void options(void *a1, size_t a2, void *a3) {
    if (a2 == 10002) {
        if (memcmp(a3, "https://md5c.", 13) == 0) {
            fakeResp = true;
        }
    }

    if (a2 == 10001) {
        userData = a3;
    }

    if (a2 == 20011) {
        callback = (callback_t)a3;
    }

    oOptions(a1, a2, a3);
}

const std::string resp =
    R"({"msg": "vpJSftgQ2noDAZR3Iri/ForvdhDZvxwlJCXowV9TgKSs+BoMyBMOIuxjpDcMTSov1thaXhg/d9aAKcpxOP6glQ3bSd8bHIGMku3Ck/33VdYhtzx4HwC4Lel5mVGZ9+2jffsIgHyIwxMl+8kYwh/QGQRlkC8zFfyNaMszsZiOxIJCy/RMYfI3buvCDPH/4D1/VxysPnaX+QtrVrs7Bt74byqnd38bi0GhpllEWL7CO+7fI+vMe2OSv6s0CUaOqzhDC5N8wIkHsthyVyP+GYoltTov3Bu5iaxmgZc/eYQPTkTWQ759pIVNjKJwnQI3EtOEdrRog6LAkA/CMGwMwBkScvY508Z3KhnNqqIIF9RpYLI6rdST+o2t5gIK4sElQg/2wHZT6wSm23t7YdxnwzEFZysv/H0y63iI4NMUmyZIkRvCyxlWVMpTt/rV9qubdbCjGDxG7A/0LbxCJBfBgEWu4Krpp1S+hk4qgIB+2apCh5sxU76mLzQdFLzNrgmbQADapyDO6rWw777F9FKlo/r9II8kISi/+2FxXp7TZE3ALbcyUo7zKucahsq7u9ucENm64D3PKV4YZCHchQY7xyYI4DaC1PQzleJxGaGbCoBQ0PZK7f33d3N3qB10OaEfe2de4uTcOKbVAjtjSLrlZcMGiZd40Bho76xCtcgAKG2FDxbH/PJo4BoIYwqiDzqpmxXBOsn0JqKLGLaAyU840GAgyLO62lE7/A26w+B9q7hkOIcKlfXZpdwjsll/dADe2U/uF5nrLxEOUGDx9gbUoB95KLD1S3KCCyaLuv8j4imt2E9EgDzk/1XdIwnbPGAECajV5z4yTpMuyD9XBhmJQIFutw==", "code": 200})";

typedef size_t (*perform_t)(void *);
perform_t oPerform = nullptr;
size_t perform(void *a1) {
    if (fakeResp == true) {
        fakeResp = false;
        std::cout << "Faking result" << std::endl;
        callback((char *)resp.c_str(), resp.size(), 1, userData);
        return 0;
    }

    return oPerform(a1);
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
    const auto expectedRegion = 0x3c7000;
    char *base = nullptr;

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
        const void *found =
            Sig::find(base, expectedRegion, "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)options, (LPVOID *)&oOptions);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found = Sig::find(base, expectedRegion, "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, perform, (LPVOID *)&oPerform);
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