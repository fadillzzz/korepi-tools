#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MinHook.h"
#include "Sig.hpp"
#include <format>
#include <inttypes.h>
#include <iostream>

bool fakeResp = false;
void *userData;
typedef size_t (*callback_t)(char *ptr, size_t size, size_t nmemb, void *userdata);
callback_t callback = nullptr;

typedef void (*options_t)(void *, size_t, void *);
options_t oOptions = nullptr;

typedef intmax_t (*strtoimax_t)(const char *nptr, char **endptr, int base);
strtoimax_t oStrtoimax = nullptr;

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
    R"({"msg": "AtZAfcAb+qtSipkXI9CP8u5XUYPGyCbGq5C/VYyt6tcelFYehMuYs0q8m/q+RwGx0/jOB3jDRAqjcqmunJpoKrIFV9W/YC9wzY+GaSU2L8oNQHlpx9KgJ0K50aqwxQD0dKiWmd16b76sLCn8GvpVrSk1k6SoFtUtPe30Cf1BkOsFD2oxSGBioUK22MkPFO2uj5xIXfZ5tC1dB4cS5ttzVlDiLPXY1hlJBqgFpZTj8znRz5qpMhflK5euefmKRPTKzwt+JHFF2YImsmDf49bMCgS6ZIwHL/jbK8dRJwFRjfkZjvpw2XxrL3wKubLqZKjUG3lHP6oKijmcWFTeu68xHphRKmqy43Gg3MZ1wCoYwcQL6tPPoqMy6TJwJdt/mBfhklPRq0XcTAjpnTIJeIo7zH/L1kFaGRAVFtqbwGLIIN08bb+7/tV3MOOc8BEp4RCb721hakBRNFqJAeYrt7yzr/VeK2igLuByrTcBkd0SOIB5LgI5K/qrMf/90bB8sfcicIgJXSVxyuuov45UXM2Rdo4YiL5M8b4LCJwhEkmplS8=", "code": 200})";

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

intmax_t strtoint(const char *nptr, char **endptr, int base) {
    if (memcmp(nptr, "1721968703399", 13) == 0) {
        return 0x1f0ed5537a7;
    }

    return oStrtoimax(nptr, endptr, base);
}

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

    // {
    //     const void *found =
    //         Sig::find(base, expectedRegion, "89 54 24 10 4C 89 44 24 18 4C 89 4C 24 20 48 83 EC 28 48 85 C9");

    //     if (found != nullptr) {
    //         MH_CreateHook((LPVOID)found, (LPVOID)options, (LPVOID *)&oOptions);
    //         MH_EnableHook((LPVOID)found);
    //     }
    // }

    // {
    //     const void *found = Sig::find(base, expectedRegion, "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D");

    //     if (found != nullptr) {
    //         MH_CreateHook((LPVOID)found, perform, (LPVOID *)&oPerform);
    //         MH_EnableHook((LPVOID)found);
    //     }
    // }

    // {
    //     MH_CreateHook((LPVOID)strtoimax, (LPVOID)strtoint, (LPVOID *)&oStrtoimax);
    //     MH_EnableHook((LPVOID)strtoimax);
    // }

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