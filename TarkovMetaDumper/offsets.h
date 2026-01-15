#pragma once
#include <iostream>
#include <windows.h>
#include <Psapi.h>
#include "./util/globals.h"
#include "util/logger.h"

namespace offsets
{
    // metadata
    PVOID s_GlobalMetadataHeader;
    PVOID metadata_key;
    PVOID get_meta_header_decrypted_value;
    PVOID get_meta_version_and_key;
    
    inline void init()
    {
        logger::info("Loading Metadata Offsets");

        HMODULE module_base = GetModuleHandleA("GameAssembly.dll");
        MODULEINFO info = {};
        GetModuleInformation(GetCurrentProcess(), module_base, &info, sizeof(MODULEINFO));
        DWORD module_size = info.SizeOfImage;

        // metadata
        s_GlobalMetadataHeader = reinterpret_cast<PVOID>(globals::find_pattern_xref( // NOLINT(performance-no-int-to-ptr)
            "48 03 3D ? ? ? ? 48 89 5E",
            reinterpret_cast<const char*>(module_base),
            module_size, 3, 7));

        metadata_key = reinterpret_cast<PVOID>(globals::find_pattern_xref( // NOLINT(performance-no-int-to-ptr)
            "48 8D 0D ? ? ? ? E8 ? ? ? ? ? ? 48 B8 ? ? ? ? ? ? ? ? 48 F7 E1 48 C1 EA ? ? ? ? ? 89 15",
            reinterpret_cast<const char*>(module_base),
            module_size, 3, 7));

        get_meta_header_decrypted_value = reinterpret_cast<PVOID>(globals::find_pattern_xref( // NOLINT(performance-no-int-to-ptr)
            "E8 ? ? ? ? ? ? 48 B8 ? ? ? ? ? ? ? ? 48 F7 E1 48 C1 EA ? ? ? ? ? 89 15",
            reinterpret_cast<const char*>(module_base),
            module_size, 1, 5));

        get_meta_version_and_key = reinterpret_cast<PVOID>(globals::find_pattern_xref( // NOLINT(performance-no-int-to-ptr)
            "E8 ? ? ? ? 8B 7C 24 ? B9",
            reinterpret_cast<const char*>(module_base),
            module_size, 1, 5));

        logger::info("Metadata Loaded");
    }
}
