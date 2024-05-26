#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MinHook.h"
#include "Sig.hpp"
#include <format>
#include <iostream>

typedef size_t (*copy_t)(void *, const char *);
copy_t oCopy = nullptr;
const auto *pubKey = "-----BEGIN PUBLIC KEY-----\n"
                     "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0SxoW83nU4qAbHXqjhal\n"
                     "MiU62ae79Ayv/EAmVfJEeCymJIpvtTqoPr99MBMDMHPxqqW1TgapD0bdAoU0vBpx\n"
                     "G5INKIQnVi1ZE0YPP1GKUXN4nchM31a9NqG4mdWXtpD/jTt40Tpxn/zaj/5kDCuP\n"
                     "o+iKQqwzKnE27Fyi0USLK82PfwCN0KlA4hmHUgB0UD+eG3VSlfHuU4ZITKqwEZFy\n"
                     "wREoekljDot8noMOQiBo0NgqmkLLK2WQ2TaTSm3A/E6d7FI+HrdPdl/GmMdTF1tf\n"
                     "lr1yMFQ1eAdOJqnmM5YxCv4FsU2qpZFFXNEbnjJ+mx549LMUWBUeRjOwZ8zXUWxd\n"
                     "oQIDAQAB\n"
                     "-----END PUBLIC KEY-----";
bool replacedPubKey = false;

size_t copy(void *a1, const char *a2) {
    if (memcmp(a2, "-----BEGIN PUBLIC KEY-----", 26) == 0 && replacedPubKey == false) {
        replacedPubKey = true;
        a2 = pubKey;
    }

    return oCopy(a1, a2);
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

const auto versionInfoResp = R"|({
    "msg": "success",
    "code": 200,
    "data": {
        "announcement": "4.6 os&cn",
        "latest_version": "1.3.1.3",
        "update_required": true,
        "update_url": "https://github.com/Cotton-Buds/calculator/releases",
        "updated_at": "2024-05-16 03:21",
        "updated_by": "Strigger(main) & Micah(auth) & EtoShinya(tech)",
        "update_diff": {
            "added_features": [
                "fix all 409",
                "Fix camera issues"
            ],
            "deleted_features": [
                "修复所有失效功能",
                "Restore all malfunctioning features."
            ],
            "total_size": "78.0 MB"
        },
        "compatible_versions": [
            "none"
        ]
    },
    "sign2": "LQuoFI+EQmj+ET67geipuHkfY0OlqPjefO4JftDJEIGZbKhV66kl8RGB4ANTHARYjmCo9OokSqTzkRJMVFyb2hM/ichoegIDsuEFtTlkR3uBmZUI43kyOHOfIEh3EWOY689RXKDGpjd20EIHDQUw7dRiAwUah9HjZG/hit1gM71d0Eqd2juhP2lMsvMn2R/F3xemK+DfOLvddzhosZyRF3p2oDlgWS7y821qbch1aMBNMFqajCHc/C3sxgkIEglHajep4+UhOhxHpeDHEhn+OX33ULVNu/+6S0FVi8J39L/xua/ACfA57KfWdSidwAZYU5rtB/sM6piXhbNUGK2wdA=="
})|";
const auto versionInfoChunkLength = std::format("{:x}", strlen(versionInfoResp));
const auto versionInfoFirstChunk = std::format("{}\r\n{}\r\n", versionInfoChunkLength, versionInfoResp);
const auto versionInfoSecondChunk = std::format("0\r\n\r\n");
const auto versionInfoAggregated = versionInfoFirstChunk + versionInfoSecondChunk;

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
    } else {
        memcpy(content, versionInfoAggregated.c_str(), versionInfoAggregated.size() + 1);
        length = versionInfoAggregated.size();
    }

    return oRespHandler(a1, content, length, a4, a5);
}

void start() {
    MH_Initialize();

    MEMORY_BASIC_INFORMATION mbi;
    bool foundBase = false;
    const auto expectedSize = 0x39d5000;
    char *base = nullptr;

    while (foundBase == false) {
        base = nullptr;
        while (VirtualQuery(base, &mbi, sizeof(mbi)) == sizeof(MEMORY_BASIC_INFORMATION)) {
            if (mbi.RegionSize == expectedSize) {
                foundBase = true;
                break;
            }

            base += mbi.RegionSize;
        }
    }

    const auto expectedRegion = 0x3cc000;

    {
        const void *found = Sig::find(base, expectedRegion,
                                      "40 53 48 83 EC 20 33 C0 0F 57 C0 0F 11 01 48 89 41 10 48 8B D9 48 89 41 18 "
                                      "49 C7 C0 FF FF FF FF 49 FF C0 42");

        MH_CreateHook((LPVOID)found, (LPVOID)copy, (LPVOID *)&oCopy);
        MH_EnableHook((LPVOID)found);
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