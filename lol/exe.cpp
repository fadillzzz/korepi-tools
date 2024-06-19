#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <format>
#include <iostream>
#include <thread>

#include "MinHook.h"
#include "Sig.hpp"

typedef char **(*hwid_t)(char **);
hwid_t oHwid = nullptr;
char **hwid(char **hwid_out) {
    auto result = oHwid(hwid_out);
    const auto s = std::string("---------Hi-Korepi-Devs---------");
    memcpy(*hwid_out, s.c_str(), s.size() + 1);
    return result;
}

bool fakeResp = false;
bool fakeVer = false;

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

        if (memcmp(a3, "https://ghp.", 12) == 0) {
            fakeVer = true;
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

const std::string versionResp = R"|({
    "msg": "success",
    "code": 200,
    "data": {
        "latest_version": "1.3.2.0",
        "update_required": true,
        "update_url": "https://github.com/Cotton-Buds/calculator/releases",
        "announcement": "4.7 os&cn",
        "updated_by": "Strigger(main) & Micah(auth) & EtoShinya(tech)",
        "updated_at": "2024-06-13 00:21",
        "update_diff": {
            "added_features": [
                "fix all 409",
                "Fix camera issues"
            ],
            "deleted_features": [
                "修复所有失效功能",
                "Restore all malfunctioning features."
            ],
            "total_size": "124 MB"
        },
        "compatible_versions": [
            "none"
        ]
    },
    "sign2": "CCDPv7klKvXwkImpFaE+WfSJxrijj4nKHH5sSOQke2rdEpd+jCkiPMU24HCulrEtEfBQEUF2H7vBAQCbb5C8za5//+b77ccfumA63fFuie9WbeLhAIyq6t+UGpu5Ecfh6iLSNyPFZANTyjs3Cn5uXoiBPKgbczCMVN2fy80uUgVqaGYznWlD6zJYla/oPmuAewnd4AHv0kidNUPu9JQI2d++9+Un+GKbsKveN2LjEsc+SdCUtHCadMuJXcMx8lMCfUkORy6q7md2HcvNBc5EZQHQ+xvBy4GHa6qYs6pOfpdZP25ixuiaYtuLyf9572Fg1R3HS3lueFbhAyKDFvn4VA=="
})|";
const std::string resp =
    R"({"msg": "vpJSftgQ2noDAZR3Iri/ForvdhDZvxwlJCXowV9TgKSs+BoMyBMOIuxjpDcMTSov1thaXhg/d9aAKcpxOP6glQ3bSd8bHIGMku3Ck/33VdYhtzx4HwC4Lel5mVGZ9+2jffsIgHyIwxMl+8kYwh/QGQRlkC8zFfyNaMszsZiOxIJCy/RMYfI3buvCDPH/4D1/VxysPnaX+QtrVrs7Bt74byqnd38bi0GhpllEWL7CO+7fI+vMe2OSv6s0CUaOqzhDC5N8wIkHsthyVyP+GYoltTov3Bu5iaxmgZc/eYQPTkTWQ759pIVNjKJwnQI3EtOEdrRog6LAkA/CMGwMwBkScvY508Z3KhnNqqIIF9RpYLI6rdST+o2t5gIK4sElQg/2wHZT6wSm23t7YdxnwzEFZysv/H0y63iI4NMUmyZIkRvCyxlWVMpTt/rV9qubdbCjGDxG7A/0LbxCJBfBgEWu4Krpp1S+hk4qgIB+2apCh5sxU76mLzQdFLzNrgmbQADapyDO6rWw777F9FKlo/r9II8kISi/+2FxXp7TZE3ALbcyUo7zKucahsq7u9ucENm64D3PKV4YZCHchQY7xyYI4DaC1PQzleJxGaGbCoBQ0PZK7f33d3N3qB10OaEfe2de4uTcOKbVAjtjSLrlZcMGiZd40Bho76xCtcgAKG2FDxbH/PJo4BoIYwqiDzqpmxXBOsn0JqKLGLaAyU840GAgyLO62lE7/A26w+B9q7hkOIcKlfXZpdwjsll/dADe2U/uF5nrLxEOUGDx9gbUoB95KLD1S3KCCyaLuv8j4imt2E9EgDzk/1XdIwnbPGAECajV5z4yTpMuyD9XBhmJQIFutw==", "code": 200})";

bool doneMagic = false;

typedef size_t (*perform_t)(void *);
perform_t oPerform = nullptr;
size_t perform(void *a1) {
    if (fakeVer == true) {
        fakeVer = false;
        callback((char *)versionResp.c_str(), versionResp.size(), 1, userData);
        return 0;
    } else if (fakeResp == true) {
        fakeResp = false;
        callback((char *)resp.c_str(), resp.size(), 1, userData);
        doneMagic = true;
        return 0;
    }

    return oPerform(a1);
}

int connectWrite() { return 1; }

const std::string readResponse =
    R"(HTTP/1.1 200 OK
Content-Length: 64
Connection: close

{"api":"time","code":"1","currentTime": 1718762445577,"msg":""})";
size_t readIdx = 0;
int read(void *a1, void *buf, int numBytes) {
    const auto ret = readResponse.substr(readIdx, numBytes);
    memcpy(buf, ret.c_str(), ret.size());
    readIdx += ret.size();
    return ret.size();
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
    if ((int64_t)hProcess != -1) {
        const auto path = std::filesystem::current_path() / "dll.dll";
        inject(hProcess, path.string());
        Sleep(2000);
    }

    return oCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                 dwCreationFlags, lpAttributeList, lpThreadId);
}

void cont() {
    const auto exe = GetModuleHandle(nullptr);
    const auto header = (PIMAGE_DOS_HEADER)exe;
    const auto nt = (PIMAGE_NT_HEADERS)((uint8_t *)exe + header->e_lfanew);
    const auto size = nt->OptionalHeader.SizeOfImage;

    {
        const void *found = Sig::find(exe, size, "48 89 5C 24 10 48 89 7C 24 18 55 48 8D 6C");

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
        const void *found = Sig::find(exe, size, "40 55 56 48 83 EC 38 48 8B F1 48 85 C9 75 0A 8D");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, perform, (LPVOID *)&oPerform);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found = Sig::find(exe, size, "40 53 B8 20 00 00 00 E8 64 6F 13 00 48 2B E0 48 83 79 30 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)connectWrite, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found =
            Sig::find(exe, size, "B8 38 00 00 00 E8 96 55 13 00 48 2B E0 45 85 C0 79 2A BA D0 00 00 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)connectWrite, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    {
        const void *found =
            Sig::find(exe, size, "B8 38 00 00 00 E8 66 5B 13 00 48 2B E0 45 85 C0 79 2A BA DF 00 00 00");

        if (found != nullptr) {
            MH_CreateHook((LPVOID)found, (LPVOID)read, nullptr);
            MH_EnableHook((LPVOID)found);
        }
    }

    std::thread([]() {
        while (doneMagic == false) {
            Sleep(1);
        }

        MH_DisableHook(MH_ALL_HOOKS);
        MH_RemoveHook(MH_ALL_HOOKS);

        {
            const auto remoteThreadEx = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateRemoteThreadEx");
            MH_CreateHook((LPVOID)remoteThreadEx, (LPVOID)createThread, (LPVOID *)&oCreateRemoteThreadEx);
            MH_EnableHook((LPVOID)remoteThreadEx);
        }
    }).detach();
}

bool restored = false;
typedef BOOL(WINAPI *WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T *);
WriteProcessMemory_t oWriteProcessMemory = nullptr;
BOOL WINAPI writeMem(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize,
                     SIZE_T *lpNumberOfBytesWritten) {
    auto result = oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);

    const auto ntdll = GetModuleHandle(L"ntdll.dll");
    uint8_t callcode = ((uint8_t *)GetProcAddress(ntdll, "NtQuerySection"))[4] - 1;
    uint8_t restore[] = {0x4C, 0x8B, 0xD1, 0xB8, callcode};

    volatile auto ntProtectVirtualMemory = (uint8_t *)GetProcAddress(ntdll, "NtProtectVirtualMemory");

    if (restored == false && ntProtectVirtualMemory == lpBaseAddress) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy(ntProtectVirtualMemory, restore, sizeof(restore));
        VirtualProtect((LPVOID)ntProtectVirtualMemory, sizeof(restore), oldProtect, nullptr);

        restored = true;

        cont();
    }

    return result;
}

void start() {
    MH_Initialize();

    MH_CreateHook((LPVOID)WriteProcessMemory, (LPVOID)writeMem, (LPVOID *)&oWriteProcessMemory);
    MH_EnableHook((LPVOID)WriteProcessMemory);
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