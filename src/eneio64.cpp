#include "eneio64.hpp"

#include <string_view>

constexpr std::wstring_view ENEIO_DEVICE_PATH = L"\\\\.\\Global\\EneIo";
constexpr uint32_t FILE_DEVICE_ENEIO = 0x00008010;

// IOCTL_WINIO_MAPPHYSTOLIN
// 0x80102040
constexpr auto IOCTL_WINIO_PHYS_MEM_MAP = CTL_CODE(FILE_DEVICE_ENEIO, 0x00000810, METHOD_BUFFERED, FILE_ANY_ACCESS);

// IOCTL_WINIO_UNMAPPHYSADDR
// 0x80102044
constexpr auto IOCTL_WINIO_PHYS_MEM_UNMAP = CTL_CODE(FILE_DEVICE_ENEIO, 0x00000811, METHOD_BUFFERED, FILE_ANY_ACCESS);

// IOCTL_WINIO_READMSR
// 0x80102058
constexpr auto IOCTL_WINIO_READMSR = CTL_CODE(FILE_DEVICE_ENEIO, 0x00000815, METHOD_BUFFERED, FILE_ANY_ACCESS);

// IOCTL_WINIO_WRITEMSR
// 0x8010205C
constexpr auto IOCTL_WINIO_WRITEMSR = CTL_CODE(FILE_DEVICE_ENEIO, 0x00000816, METHOD_BUFFERED, FILE_ANY_ACCESS);

bool eneio64::physical_map(uint64_t address, uint64_t size, HANDLE* section, void** section_address, HANDLE* section_handle) {
    eneio64_request request {
        size,
        address,
        nullptr,
        nullptr,
        nullptr
    };

    DWORD bytes_returned;
    if (DeviceIoControl(driver_handle,
                        IOCTL_WINIO_PHYS_MEM_MAP,
                        &request,
                        sizeof(request),
                        &request,
                        sizeof(request),
                        &bytes_returned,
                        nullptr)) {
        *section = request.section;
        *section_address = request.section_address;
        *section_handle = request.section_handle;

        return true;
    }

    return false;
}

bool eneio64::physical_unmap(HANDLE section, void* section_address, HANDLE section_handle) {
    eneio64_request request {
            0,
            0,
            section,
            section_address,
            section_handle
    };

    DWORD bytes_returned;
    return DeviceIoControl(driver_handle,
                           IOCTL_WINIO_PHYS_MEM_UNMAP,
                           &request,
                           sizeof(request),
                           &request,
                           sizeof(request),
                           &bytes_returned,
                           nullptr);
}

bool eneio64::read(uint64_t address, void* buffer, size_t size) {
    HANDLE section = INVALID_HANDLE_VALUE;
    void* section_address = nullptr;
    HANDLE section_handle = INVALID_HANDLE_VALUE;

    if (!physical_map(address, size, &section, &section_address, &section_handle))
        return false;

    __try {
        return memcpy(buffer, section_address, size) != nullptr;
    }
    __finally {
        physical_unmap(section, section_address, section_handle);
    }
}

bool eneio64::write(uint64_t address, const void* buffer, size_t size) {
    HANDLE section = INVALID_HANDLE_VALUE;
    void* section_address = nullptr;
    HANDLE section_handle = INVALID_HANDLE_VALUE;

    if (!physical_map(address, size, &section, &section_address, &section_handle) != 0)
        return false;

    __try {
        return memcpy(section_address, buffer, size) != nullptr;
    }
    __finally {
        physical_unmap(section, section_address, section_handle);
    }
}

bool eneio64::initialize() {
    if (driver_handle != INVALID_HANDLE_VALUE)
        return true;

    driver_handle = CreateFileW(ENEIO_DEVICE_PATH.data(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                0,
                                nullptr);

    return driver_handle != INVALID_HANDLE_VALUE;
}

bool eneio64::cleanup() {
    if (driver_handle == INVALID_HANDLE_VALUE)
        return false;

    (void) CloseHandle(driver_handle);

    driver_handle = INVALID_HANDLE_VALUE;

    return true;
}

eneio64::~eneio64() {
    cleanup();
}