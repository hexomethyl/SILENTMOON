#ifndef PTE_HPP
#define PTE_HPP

#include "ia32.h"

#define PAGE_SHIFT 12

constexpr uint64_t PAGE_4KB = 0x1000;
constexpr uint64_t PAGE_2MB = PAGE_4KB * 512;
constexpr uint64_t PAGE_1GB = PAGE_2MB * 512;

constexpr uint64_t PFN_TO_PAGE(uint64_t value) {
    return (value << PAGE_SHIFT);
}

// get PML4 address from CR3 register value
// Bits 51-12 in CR3 contains PML4 base address
constexpr uint64_t PML4_ADDRESS(uint64_t value) {
    return (value & 0xFFFFFFFFFFFFF000);
}

// Get address translation indexes from virtual address
constexpr uint64_t PML4_INDEX(uint64_t value) {
    // Bits 48-39 of VA contains 9 bit PML4 index
    return ((value >> 39) & 0x1FF);
}

constexpr uint64_t PDPT_INDEX(uint64_t value) {
    // Bits 39-30 of VA contains 9 bit PDPT index
    return ((value >> 30) & 0x1FF);
}

constexpr uint64_t PDE_INDEX(uint64_t value) {
    // Bits 30-21 of VA contains 9 bit PDE index
    return ((value >> 21) & 0x1FF);
}

constexpr uint64_t PTE_INDEX(uint64_t value) {
    // Bits 12-0 of VA contains 9 bit PTE index
    return ((value >> 12) & 0x1FF);
}

// Page offset helpers
constexpr uint64_t PAGE_OFFSET_4K(uint64_t value) {
    // Mask for 4KB page offset (12 bits)
    return (value & 0xFFF);
}

constexpr uint64_t PAGE_OFFSET_2M(uint64_t value) {
    // Mask for 2MB page offset (21 bits)
    return (value & 0x1FFFFF);
}

constexpr uint64_t PAGE_OFFSET_1G(uint64_t value) {
    // Mask for 1GB page offset (30 bits)
    return (value & 0x3FFFFFFF);
}

#endif