#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MinHook.h"
#include "Sig.hpp"
#include <format>
#include <iostream>

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
        const void *found = Sig::find(base, expectedRegion, "48 89 5C 24 20 56 57 41 54 41 55 41 56 48 83 EC 20");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)respHandler, (LPVOID *)&oRespHandler);
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