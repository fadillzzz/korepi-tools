#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <cstdint>
#include <filesystem>
#include <format>
#include <iostream>

#include "MinHook.h"
#include "Sig.hpp"

typedef char **(*hwid_t)(char **);
hwid_t oHwid = nullptr;

char **hwid(char **ret) {
    oHwid(ret);
    const auto s = std::string("---------Hi-Korepi-Devs---------");
    memcpy(*ret, s.c_str(), s.size() + 1);

    return ret;
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

const auto resp = R"({
    "msg": "Hi there",
    "code": 200,
    "data": {
        "createBy": null,
        "createTime": "2024-05-25T14:06:09.662Z",
        "updateBy": "anonymousUser",
        "updateTime": "2024-05-25T14:06:09.662Z",
        "delFlag": 0,
        "remark": "Oops!",
        "id": 44262,
        "roleValue": 25,
        "cardKey": null,
        "expiryTime": "2038-01-19T03:14:07.000Z",
        "lastLoginTime": "2024-05-25T14:06:09.662Z",
        "hwid": "---------Hi-Korepi-Devs---------",
        "fileMd5": "mokPVuACUwR5Qw==",
        "resetTime": null,
        "resetNum": 4,
        "pauseTime": null,
        "status": 0
    },
    "signature": "a5879201e7fb4e3064390fccb0d8bbcf628c70bb237843101f314710ebfa0adc",
    "sign2": "coUVZrl9x43Dql30LoOOpp/U7+gVb7298CeYu6uu8gT1RRxsf4jvyz/xQckiDWd5Sj43dl5AAzdmJGPPFtyQC3haU20H6v09C6whJqSwHDuizT+SW7VFZbWT3jhc+y1bgkYEhbyxHK9hkTGF8hlMk6HSkhAg1vl8t/E7ZcScmh22ZRYXMRijZEEPCgNbDTXDwySqdRnEaLc17z4uvGG/+B2C/60T4aH4VFnFjDyCuIlxCOgMOUM3QcXj0KZakmHxddURpAULfBi00LCamJlJIeUFbnlg3vcrNoCxD/jpHmdZn0jr30jXpgljhAb5AxsX1xwdF5wYROiJTWv6U6nm0A=="
})";
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
    if ((int64_t)hProcess != -1) {
        const auto path = std::filesystem::current_path() / "dll.dll";
        inject(hProcess, path.string());
        Sleep(2000);
    }

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
            "48 89 5C 24 10 48 89 74 24 18 48 89 7C 24 20 55 41 54 41 55 41 56 41 57 48 8D 6C 24 C9 48 81 EC C0");

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

    {
        const auto remoteThreadEx = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "CreateRemoteThreadEx");
        MH_CreateHook((LPVOID)remoteThreadEx, (LPVOID)createThread, (LPVOID *)&oCreateRemoteThreadEx);
        MH_EnableHook((LPVOID)remoteThreadEx);
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