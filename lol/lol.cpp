#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <TlHelp32.h>
#include <filesystem>
#include <iostream>
#include <tchar.h>
#include <thread>

#include "MinHook.h"
#include "Sig.hpp"

DWORD getProcId(const wchar_t *procName) {
    DWORD procId = 0;
    HANDLE handleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (handleSnapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 procEntry;
        procEntry.dwSize = sizeof(procEntry);

        while (Process32Next(handleSnapshot, &procEntry)) {
            if (_wcsicmp(procEntry.szExeFile, procName) == 0) {
                procId = procEntry.th32ProcessID;
                break;
            }
        }
    }

    CloseHandle(handleSnapshot);

    return procId;
}

int start() {
    DWORD procId = 0;

    std::cout << "Waiting for GenshinImpact.exe to start..." << std::endl;

    while (procId == 0) {
        procId = getProcId(L"GenshinImpact.exe");
        Sleep(1);
    }

    try {
        HANDLE proc = OpenProcess(PROCESS_ALL_ACCESS, false, procId);

        if (proc == nullptr) {
            throw new std::runtime_error("Could not open process");
        }

        char *base = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        bool foundBase = false;
        const auto expectedSize = 0x39d5000;

        std::cout << "Searching for base address..." << std::endl;

        while (VirtualQueryEx(proc, base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
            if (mbi.RegionSize == expectedSize) {
                foundBase = true;
                break;
            }

            base += mbi.RegionSize;
        }

        if (!foundBase) {
            throw new std::runtime_error("Could not find base address. Potential version mismatch.");
        }

        std::cout << "Base address: " << (void *)base << std::endl;
        std::cout << "Region size: " << std::hex << mbi.RegionSize << std::endl;

        const auto expectedRegion = 0x3cc000;

        char *buf = new char[expectedRegion];
        if (!ReadProcessMemory(proc, base, (void *)buf, expectedRegion, NULL)) {
            throw new std::runtime_error("Could not read process memory");
        }

        {
            const void *found =
                Sig::find(buf, expectedRegion, "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 20 48 8B DA E8");

            if (found == nullptr) {
                throw new std::runtime_error("Pattern not found");
            }

            const auto relative = (char *)found - buf;
            const auto absolute = (uintptr_t)base + relative;
            const auto endOfMappedMemory = (uintptr_t)base + expectedSize;

            std::cout << "Pattern found at (relative): " << std::hex << relative << std::endl;
            std::cout << "Pattern found at (absolute): " << std::hex << absolute << std::endl;

            const auto defaultCertPath = std::string("C:\\WINDOWS\\system32\\drivers\\etc\\server_pubkey.pem");
            std::cout << "Please input the path to your md5c.korepi.com.pub file:" << std::endl;
            std::string certPath;
            std::cin >> certPath;

            const auto defaultPathAddr =
                VirtualAllocEx(proc, nullptr, defaultCertPath.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (defaultPathAddr == nullptr) {
                throw new std::runtime_error("Could not allocate memory for default path");
            }

            std::cout << "Default path address: " << std::hex << defaultPathAddr << std::endl;

            if (!WriteProcessMemory(proc, defaultPathAddr, defaultCertPath.c_str(), defaultCertPath.size(), NULL)) {
                throw new std::runtime_error("Could not write default path to process memory");
            }

            const auto pathAddr =
                VirtualAllocEx(proc, nullptr, certPath.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pathAddr == nullptr) {
                throw new std::runtime_error("Could not allocate memory for path");
            }

            std::cout << "Path address: " << std::hex << pathAddr << std::endl;

            if (!WriteProcessMemory(proc, pathAddr, certPath.c_str(), certPath.size(), NULL)) {
                throw new std::runtime_error("Could not write path to process memory");
            }

            // Better pray that the address is near LOL
            const auto codeAddr =
                VirtualAllocEx(proc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (codeAddr == nullptr) {
                throw new std::runtime_error("Could not allocate memory for code");
            }

            std::cout << "Code address: " << std::hex << codeAddr << std::endl;

            const auto relativeJump = (char *)codeAddr - (char *)absolute - 5;
            const int relativeJumpBack = (char *)absolute - (char *)codeAddr - 0x30;

            uint8_t instructions[] = {
                0x56,                                                       // push rsi
                0x57,                                                       // push rdi
                0xfc,                                                       // cld
                0x48, 0x89, 0xce,                                           // mov rsi, rcx
                0x48, 0x31, 0xc9,                                           // xor rcx, rcx
                0xb1, 0x31,                                                 // mov cl, 0x31
                0x48, 0xbf, 0x0d, 0xf0, 0xad, 0xba, 0x0d, 0xf0, 0xad, 0xba, // mov rdi, 0xbaadf00dbaadf00d
                0xf3, 0xa6,                                                 // rep cmpsb
                0x48, 0xbf, 0xde, 0xc0, 0xad, 0xba, 0xde, 0xc0, 0xad, 0xba, // mov rdi, 0xbaadc0debaadc0de
                0x48, 0x0f, 0x44, 0xcf,                                     // cmove rcx, rdi
                0x48, 0x0f, 0x45, 0xce,                                     // cmovne rcx, rsi
                0x5f,                                                       // pop rdi
                0x5e,                                                       // pop rsi
                0x48, 0x89, 0x5c, 0x24, 0x08,                               // mov [rsp+0x8], rbx; original instruction
                0xe9, 0x00, 0x00, 0x00, 0x00,                               // jmp 0
            };

            memcpy(&instructions[0xD], &defaultPathAddr, sizeof(defaultPathAddr));
            memcpy(&instructions[0x19], &pathAddr, sizeof(pathAddr));
            memcpy(&instructions[0x31], &relativeJumpBack, sizeof(relativeJumpBack));

            if (!WriteProcessMemory(proc, codeAddr, instructions, sizeof(instructions), NULL)) {
                throw new std::runtime_error("Could not write instructions to process memory");
            }

            WriteProcessMemory(proc, (void *)absolute, "\xE9", 1, NULL);
            WriteProcessMemory(proc, (void *)(absolute + 1), &relativeJump, 4, NULL);
        }

        {
            const void *hookAddr =
                Sig::find(buf, expectedRegion,
                          "40 53 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 48 8B D9 48 89 41 18 "
                          "49 C7 C0 FF FF FF FF 49 FF C0 42");

            if (hookAddr == nullptr) {
                throw new std::runtime_error("Second pattern not found");
            }

            const auto relative = (char *)hookAddr - buf;
            const auto absolute = (uintptr_t)base + relative;
            const auto endOfMappedMemory = (uintptr_t)base + expectedSize;

            const auto pubKey = "-----BEGIN PUBLIC KEY-----\n"
                                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SxoW83nU4qAbHXqjhal\n"
                                "MiU62ae79Ayv/EAmVfJEeCymJIpvtTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpx\n"
                                "G5INKIQnVi1ZE0YPP1GKUXN4nchM31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuP\n"
                                "o+iKQqwzKnE27Fyi0USLK82PfwCN0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFy\n"
                                "wREoekljDot8noMOQiBo0NgqmkLLK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tf\n"
                                "lr1yMFQ1eAdOJqnmM5YxCv4FsU2qpZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxd\n"
                                "oQIDAQAB\n"
                                "-----END PUBLIC KEY-----";

            const auto pubKeyAddr =
                VirtualAllocEx(proc, nullptr, strlen(pubKey), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

            if (pubKeyAddr == nullptr) {
                throw new std::runtime_error("Could not allocate memory for public key");
            }

            std::cout << "Public key address: " << std::hex << pubKeyAddr << std::endl;

            if (!WriteProcessMemory(proc, pubKeyAddr, pubKey, strlen(pubKey), NULL)) {
                throw new std::runtime_error("Could not write public key to process memory");
            }

            std::cout << "Second pattern found at (relative): " << std::hex << relative << std::endl;
            std::cout << "Second pattern found at (absolute): " << std::hex << absolute << std::endl;

            // Better pray that the address is near LOL
            const auto codeAddr =
                VirtualAllocEx(proc, nullptr, 0x100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

            if (codeAddr == nullptr) {
                throw new std::runtime_error("Could not allocate memory for code");
            }

            std::cout << "Second code address: " << std::hex << codeAddr << std::endl;

            const auto relativeJump = (char *)codeAddr - (char *)absolute - 5;
            const int relativeJumpBack = (char *)absolute - (char *)codeAddr - 0x51;

            uint8_t instructions[] = {
                0x41, 0x52,                                                 // push r10
                0x41, 0x51,                                                 // push r9
                0x49, 0xb9, 0xde, 0xc0, 0xad, 0xba, 0xde, 0xc0, 0xad, 0xba, // mov r9, 0xbaadc0debaadc0de
                0x4D, 0x8D, 0x91, 0xd0, 0x61, 0x56, 0x00,                   // lea r10, [r9+0x5722C0]
                0x4C, 0x39, 0xD1,                                           // cmp rcx, r10
                0x41, 0x59,                                                 // pop r9
                0x41, 0x5A,                                                 // pop r10
                0x75, 0x2e,                                                 // jne $+47
                0x41, 0x50,                                                 // push r8
                0x41, 0x51,                                                 // push r9
                0x50,                                                       // push rax
                0x48, 0x31, 0xc0,                                           // xor rax, rax
                0x4d, 0x31, 0xc9,                                           // xor r9, r9
                0x49, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE, // mov r8, 0xdeadbeefdeadbeef
                0x43, 0x8a, 0x04, 0x08,                                     // mov al, [r8+r9]
                0x42, 0x88, 0x04, 0x0a,                                     // mov [rdx+r9], al
                0x49, 0xFF, 0xC1,                                           // inc r9
                0x49, 0x81, 0xf9, 0xc2, 0x01, 0x00, 0x00,                   // cmp r9, 0x1c2
                0x75, 0xec,                                                 // jne $-20
                0x58,                                                       // pop rax
                0x41, 0x59,                                                 // pop r9
                0x41, 0x58,                                                 // pop r8
                0x53,                                                       // push rbx
                0x48, 0x83, 0xEC, 0x20,                                     // sub rsp, 0x20
                0xE9, 0x00, 0x00, 0x00, 0x00                                // jmp 0
            };

            memcpy(&instructions[0x6], &base, sizeof(base));
            memcpy(&instructions[0x2B], &pubKeyAddr, sizeof(pubKeyAddr));
            memcpy(&instructions[0x52], &relativeJumpBack, sizeof(relativeJumpBack));

            if (!WriteProcessMemory(proc, codeAddr, instructions, sizeof(instructions), NULL)) {
                throw new std::runtime_error("Could not write instructions to process memory");
            }

            WriteProcessMemory(proc, (void *)absolute, "\xE9", 1, NULL);
            WriteProcessMemory(proc, (void *)(absolute + 1), &relativeJump, 4, NULL);
            WriteProcessMemory(proc, (void *)(absolute + 5), "\x90", 1, NULL);
        }

        std::cout << "Finished writing to process memory" << std::endl;
    } catch (const std::exception &e) {
        std::cout << "Exception: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

typedef HANDLE (*CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD,
                                         LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
CreateRemoteThreadEx_t oCreateRemoteThreadEx = nullptr;

HANDLE WINAPI hookCreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize,
                                       LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags,
                                       LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList, LPDWORD lpThreadId) {
    if ((int64_t)hProcess > 0) {
        start();
    }

    return oCreateRemoteThreadEx(hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
                                 dwCreationFlags, lpAttributeList, lpThreadId);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        MH_Initialize();

        MH_CreateHook((LPVOID)CreateRemoteThreadEx, hookCreateRemoteThreadEx, (LPVOID *)&oCreateRemoteThreadEx);
        MH_EnableHook((LPVOID)CreateRemoteThreadEx);
    }

    return true;
}
