#pragma once
#include <fstream>

#include "offsets.h"
#include "libil2cpp/GlobalMetadataFileInternals.h"
#include "libs/detours.h"
#include "util/logger.h"

namespace metadata
{
    uint32_t request_key = 0;

    PVOID o_get_meta_version_and_key = nullptr;

    inline void hk_get_meta_version_and_key(uint32_t* key, uint32_t* version);

    inline void hook_key_function()
    {
        logger::info("Hooking Meta Key Function");
        DetourUpdateThread(GetCurrentThread());
        DetourTransactionBegin();
        o_get_meta_version_and_key = offsets::get_meta_version_and_key;
        DetourAttach(&o_get_meta_version_and_key, reinterpret_cast<PVOID>(hk_get_meta_version_and_key));
        DetourTransactionCommit();
        logger::info("Meta Key Function Hooked");
    }

    inline void unhook_key_function()
    {
        DetourUpdateThread(GetCurrentThread());
        DetourTransactionBegin();
        DetourDetach(&o_get_meta_version_and_key, reinterpret_cast<PVOID>(hk_get_meta_version_and_key));
        DetourTransactionCommit();
    }

    inline void hk_get_meta_version_and_key(uint32_t* key, uint32_t* version)
    {
        logger::info("Meta Key Function Called");
        reinterpret_cast<void(*)(uint32_t*, uint32_t*)>(o_get_meta_version_and_key)(key, version);
        request_key = *key;
        unhook_key_function();
        logger::info("Meta Key Function Unhooked");
    }

    // still not sure how to reverse this so i skidded
    // 48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 55 48 8D AC 24 ? ? ? ? 48 81 EC ? ? ? ? 89 8D
    // https://www.unknowncheats.me/forum/escape-from-tarkov/726047-tarkov-il2cpp-decryption.html
    inline uint32_t transform_key(uint32_t value)
    {
        value = value % 0x8BA;
        value = value * 0x1657A1;
        value = value + 0x3CF8479F;
        value = value % 0xC4653218;

        return value;
    }

    // 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC ? 8D 7A
    inline void generate_field_order_type(uint32_t* field_order, uint32_t field_count)
    {
        uint32_t transformed = transform_key(request_key);

        for (auto i = 0u; i < field_count; i++)
            field_order[i] = i;

        for (auto i = 0u; i < field_count; i++)
        {
            const auto i0 = field_count - i - 1;
            const auto i1 = transformed % (i0 + 1);

            std::swap(field_order[i0], field_order[i1]);
        }
    }

    template <typename T>
    void reorder_struct(PVOID meta, uint32_t field_count, int field_sizes[], size_t offset, size_t count,
                        PVOID field_order_generator)
    {
        auto field_order = new uint32_t[field_count];
        auto generator = reinterpret_cast<void(*)(uint32_t*, uint32_t)>(field_order_generator);
        generator(field_order, field_count);

        int* Il2CppTypeDefinition_fields_size = field_sizes;
        auto Il2CppTypeDefinition_fields_offsets = new int[field_count];

        {
            uint32_t current_offset = 0;
            for (auto i = 0u; i < field_count; i++)
            {
                const auto field = field_order[i];

                Il2CppTypeDefinition_fields_offsets[field] = static_cast<int>(current_offset);
                current_offset += Il2CppTypeDefinition_fields_size[field];
            }
        }


        const auto raw_offset = *reinterpret_cast<uint32_t*>(reinterpret_cast<UINT64>(meta) + // NOLINT(performance-no-int-to-ptr)
            offset);
        const auto raw_size = *reinterpret_cast<uint32_t*>(reinterpret_cast<UINT64>(meta) + // NOLINT(performance-no-int-to-ptr)
            count);

        uint32_t current_type_definition_offset = 0;
        while (current_type_definition_offset < raw_size)
        {
            auto typeDefinitionSize = sizeof(T);
            const auto type_definition_data = reinterpret_cast<char*>(reinterpret_cast<UINT64>(meta) + raw_offset + // NOLINT(performance-no-int-to-ptr)
                current_type_definition_offset);

            auto reordered_type_definition = new uint8_t[typeDefinitionSize];
            uint32_t current_offset = 0;
            for (auto i = 0u; i < field_count; i++)
            {
                memcpy(reordered_type_definition + current_offset,
                       type_definition_data + Il2CppTypeDefinition_fields_offsets[i],
                       Il2CppTypeDefinition_fields_size[i]);
                current_offset += Il2CppTypeDefinition_fields_size[i];
            }

            memcpy(type_definition_data, reordered_type_definition, typeDefinitionSize);
            current_type_definition_offset += static_cast<uint32_t>(typeDefinitionSize);

            delete[] reordered_type_definition;
        }

        delete[] Il2CppTypeDefinition_fields_offsets;
        delete[] field_order;
    }

    template <typename T>
    void read_all_names(PVOID meta, Il2CppGlobalMetadataHeader header, int32_t offset, int32_t size, size_t name_offset)
    {
        for (size_t i = 0; i < size / sizeof(T); ++i)
        {
            auto type = reinterpret_cast<T*>(static_cast<char*>(meta) + offset + i * sizeof(T));

            auto name =
                static_cast<char*>(meta) + header.stringOffset + *reinterpret_cast<int*>(reinterpret_cast<char*>(type) +
                    name_offset);
            std::cout << name << "\n";
        }
    }

    inline void decrypt()
    {
        logger::info("Decrypting Metadata");
        auto get_meta_header_decrypted_value = reinterpret_cast<int32_t*(*)(PVOID, PVOID)>(
            offsets::get_meta_header_decrypted_value);

        PVOID metaPtr = *static_cast<PVOID*>(
            offsets::s_GlobalMetadataHeader);

        Il2CppGlobalMetadataHeader metadata_header = *static_cast<Il2CppGlobalMetadataHeader*>(metaPtr);

        // calculate meta size
        size_t size = sizeof(Il2CppGlobalMetadataHeader);

        // decrypt values
        auto headerPtr = reinterpret_cast<int32_t*>(&metadata_header);
        for (size_t i = 0; i < sizeof(Il2CppGlobalMetadataHeader) / sizeof(int32_t); i += 2)
        {
            int32_t size_encrypted = headerPtr[i];
            int32_t size_decrypted = *get_meta_header_decrypted_value(offsets::metadata_key, &size_encrypted);

            int32_t offset_encrypted = headerPtr[i + 1];
            int32_t offset_decrypted = *get_meta_header_decrypted_value(offsets::metadata_key, &offset_encrypted);

            // swap size and offset props, they are in the wrong order
            headerPtr[i] = offset_decrypted;
            headerPtr[i + 1] = size_decrypted;

            size += size_decrypted;
        }

        // set magic and version because its blank
        metadata_header.sanity = static_cast<int32_t>(0xFAB11BAF);
        metadata_header.version = 0x1F;

        // fix nested types count, not sure why but there is some invalid data at the end
        metadata_header.nestedTypesSize -= sizeof(NestedTypeIndex) * 5;

        // copy out meta
        PVOID meta = malloc(size);
        memcpy(meta, metaPtr, size);

        // add decrypted headers
        memcpy(meta, &metadata_header, sizeof(Il2CppGlobalMetadataHeader));

        // reordering type definition
        int type_field_sizes[] = {
            4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 2, 2, 2, 2, 2, 2, 2, 2, 4, 4
        };
        reorder_struct<Il2CppTypeDefinition>(
            meta,
            26u,
            type_field_sizes,
            FIELD_OFFSET(Il2CppGlobalMetadataHeader, typeDefinitionsOffset),
            FIELD_OFFSET(Il2CppGlobalMetadataHeader, typeDefinitionsSize),
            reinterpret_cast<PVOID>(generate_field_order_type)
        );

        // write file
        std::ofstream out("global-metadata.dat", std::ios::binary);
        out.write(static_cast<const char*>(meta), static_cast<std::streamsize>(size));
        out.close();

        // done
        free(meta);
        logger::info("Decrypted Metadata");
    }
};
