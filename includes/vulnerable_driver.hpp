#ifndef VULN_DRIVER_HPP
#define VULN_DRIVER_HPP

#include <cstdint>

class vulnerable_driver {
public:
    virtual bool read(uint64_t address, void* buffer, size_t length) = 0;
    virtual bool write(uint64_t address, const void* buffer, size_t length) = 0;
};

#endif