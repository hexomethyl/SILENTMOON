#ifndef ENEIO64_HPP
#define ENEIO64_HPP

#include "sdk.hpp"
#include "vulnerable_driver.hpp"

class eneio64 : public vulnerable_driver {
    struct eneio64_request {
        size_t size;
        uint64_t address;
        HANDLE section;
        void* section_address;
        HANDLE section_handle;
    };
    HANDLE driver_handle = INVALID_HANDLE_VALUE;
public:
    bool initialize();
    bool cleanup();
    bool physical_map(uint64_t address, size_t size, HANDLE* section, void** section_address, HANDLE* section_handle);
    bool physical_unmap(HANDLE section, void* section_address, HANDLE section_handle);
    bool read(uint64_t address, void* buffer, size_t length) override;
    bool write(uint64_t address, const void* buffer, size_t length) override;
    ~eneio64();
};

#endif