#ifndef SDK_HPP
#define SDK_HPP

#include <cstdint>

#define PHNT_VERSION PHNT_WIN11
#define PHNT_MODE PHNT_MODE_USER
#include <phnt.h>

/*
    https://github.com/Cr4sh/KernelForge/blob/master/kforge_driver/kforge_driver.cpp#L11
    PROCESSOR_START_BLOCK is allocated by winload.efi, so it could be
    anywhere in the low memory.
*/
constexpr uint32_t PROCESSOR_START_BLOCK_MIN = 0;
constexpr uint32_t PROCESSOR_START_BLOCK_MAX = 0x10000;
constexpr uint32_t SYSTEM_PID = 4;

// ************************************************************** PROCESSOR_START_BLOCK ********************************************************************

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L1027
typedef union _KGDTENTRY64 {
    struct {
        USHORT  LimitLow;
        USHORT  BaseLow;
        union {
            struct {
                UCHAR   BaseMiddle;
                UCHAR   Flags1;
                UCHAR   Flags2;
                UCHAR   BaseHigh;
            } Bytes;

            struct {
                ULONG   BaseMiddle : 8;
                ULONG   Type : 5;
                ULONG   Dpl : 2;
                ULONG   Present : 1;
                ULONG   LimitHigh : 4;
                ULONG   System : 1;
                ULONG   LongMode : 1;
                ULONG   DefaultBig : 1;
                ULONG   Granularity : 1;
                ULONG   BaseHigh : 8;
            } Bits;
        };

        ULONG BaseUpper;
        ULONG MustBeZero;
    };

    ULONG64 Alignment;
} KGDTENTRY64, *PKGDTENTRY64;

// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L1157
// Define pseudo descriptor structures for both 64- and 32-bit mode.
//

typedef struct _KDESCRIPTOR {
    USHORT Pad[3];
    USHORT Limit;
    PVOID Base;
} KDESCRIPTOR, *PKDESCRIPTOR;

typedef struct _KDESCRIPTOR32 {
    USHORT Pad[3];
    USHORT Limit;
    ULONG Base;
} KDESCRIPTOR32, *PKDESCRIPTOR32;

//
// Define special kernel registers and the initial MXCSR value.
//

typedef struct _KSPECIAL_REGISTERS {
    ULONG64 Cr0;
    ULONG64 Cr2;
    ULONG64 Cr3;
    ULONG64 Cr4;
    ULONG64 KernelDr0;
    ULONG64 KernelDr1;
    ULONG64 KernelDr2;
    ULONG64 KernelDr3;
    ULONG64 KernelDr6;
    ULONG64 KernelDr7;
    KDESCRIPTOR Gdtr;
    KDESCRIPTOR Idtr;
    USHORT Tr;
    USHORT Ldtr;
    ULONG MxCsr;
    ULONG64 DebugControl;
    ULONG64 LastBranchToRip;
    ULONG64 LastBranchFromRip;
    ULONG64 LastExceptionToRip;
    ULONG64 LastExceptionFromRip;
    ULONG64 Cr8;
    ULONG64 MsrGsBase;
    ULONG64 MsrGsSwap;
    ULONG64 MsrStar;
    ULONG64 MsrLStar;
    ULONG64 MsrCStar;
    ULONG64 MsrSyscallMask;
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

//
// Define processor state structure.
//

typedef struct _KPROCESSOR_STATE {
    KSPECIAL_REGISTERS SpecialRegisters;
    CONTEXT ContextFrame;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;


// https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/inc/amd64.h#L3305
// Structure to aid in booting secondary processors
//

#pragma pack(push, 2)

typedef struct _FAR_JMP_16 {
    UCHAR  OpCode;  // = 0xe9
    USHORT Offset;
} FAR_JMP_16;

typedef struct _FAR_TARGET_32 {
    ULONG Offset;
    USHORT Selector;
} FAR_TARGET_32;

typedef struct _PSEUDO_DESCRIPTOR_32 {
    USHORT Limit;
    ULONG Base;
} PSEUDO_DESCRIPTOR_32;

#pragma pack(pop, 2)

constexpr uint32_t PSB_GDT32_NULL   = 0 * 16;
constexpr uint32_t PSB_GDT32_CODE64 = 1 * 16;
constexpr uint32_t PSB_GDT32_DATA32 = 2 * 16;
constexpr uint32_t PSB_GDT32_CODE32 = 3 * 16;
constexpr uint32_t PSB_GDT32_MAX    = 3;

typedef struct _PROCESSOR_START_BLOCK *PPROCESSOR_START_BLOCK;
typedef struct _PROCESSOR_START_BLOCK {

    //
    // The block starts with a jmp instruction to the end of the block
    //

    FAR_JMP_16 Jmp;

    //
    // Completion flag is set to non-zero when the target processor has
    // started
    //

    ULONG CompletionFlag;

    //
    // Pseudo descriptors for GDT and IDT.
    //

    PSEUDO_DESCRIPTOR_32 Gdt32;
    PSEUDO_DESCRIPTOR_32 Idt32;

    //
    // The temporary 32-bit GDT itself resides here.
    //

    KGDTENTRY64 Gdt[PSB_GDT32_MAX + 1];

    //
    // Physical address of the 64-bit top-level identity-mapped page table.
    //

    ULONG64 TiledCr3;

    //
    // Far jump target from Rm to Pm code
    //

    FAR_TARGET_32 PmTarget;

    //
    // Far jump target from Pm to Lm code
    //

    FAR_TARGET_32 LmIdentityTarget;

    //
    // Address of LmTarget
    //

    PVOID LmTarget;

    //
    // Linear address of this structure
    //

    PPROCESSOR_START_BLOCK SelfMap;

    //
    // Contents of the PAT msr
    //

    ULONG64 MsrPat;

    //
    // Contents of the EFER msr
    //

    ULONG64 MsrEFER;

    //
    // Initial processor state for the processor to be started
    //

    KPROCESSOR_STATE ProcessorState;

} PROCESSOR_START_BLOCK;

// ************************************************************** RESOURCE_DESCRIPTOR ********************************************************************

// // https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2210%2022H2%20(May%202023%20Update)/_CM_PARTIAL_RESOURCE_DESCRIPTOR
// //0x14 bytes (sizeof)
#pragma pack(push, 4)
 struct _CM_PARTIAL_RESOURCE_DESCRIPTOR
{
    UCHAR Type;                                                             //0x0
    UCHAR ShareDisposition;                                                 //0x1
    USHORT Flags;                                                           //0x2
    union
    {
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length;                                                   //0xc
        } Generic;                                                          //0x4
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length;                                                   //0xc
        } Port;                                                             //0x4
        struct
        {
            USHORT Level;                                                   //0x4
            USHORT Group;                                                   //0x6
            ULONG Vector;                                                   //0x8
            ULONGLONG Affinity;                                             //0xc
        } Interrupt;                                                        //0x4
        struct
        {
            union
            {
                struct
                {
                    USHORT Group;                                           //0x4
                    USHORT MessageCount;                                    //0x6
                    ULONG Vector;                                           //0x8
                    ULONGLONG Affinity;                                     //0xc
                } Raw;                                                      //0x4
                struct
                {
                    USHORT Level;                                           //0x4
                    USHORT Group;                                           //0x6
                    ULONG Vector;                                           //0x8
                    ULONGLONG Affinity;                                     //0xc
                } Translated;                                               //0x4
            };
        } MessageInterrupt;                                                 //0x4
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length;                                                   //0xc
        } Memory;                                                           //0x4
        struct
        {
            ULONG Channel;                                                  //0x4
            ULONG Port;                                                     //0x8
            ULONG Reserved1;                                                //0xc
        } Dma;                                                              //0x4
        struct
        {
            ULONG Channel;                                                  //0x4
            ULONG RequestLine;                                              //0x8
            UCHAR TransferWidth;                                            //0xc
            UCHAR Reserved1;                                                //0xd
            UCHAR Reserved2;                                                //0xe
            UCHAR Reserved3;                                                //0xf
        } DmaV3;                                                            //0x4
        struct
        {
            ULONG Data[3];                                                  //0x4
        } DevicePrivate;                                                    //0x4
        struct
        {
            ULONG Start;                                                    //0x4
            ULONG Length;                                                   //0x8
            ULONG Reserved;                                                 //0xc
        } BusNumber;                                                        //0x4
        struct
        {
            ULONG DataSize;                                                 //0x4
            ULONG Reserved1;                                                //0x8
            ULONG Reserved2;                                                //0xc
        } DeviceSpecificData;                                               //0x4
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length40;                                                 //0xc
        } Memory40;                                                         //0x4
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length48;                                                 //0xc
        } Memory48;                                                         //0x4
        struct
        {
            union _LARGE_INTEGER Start;                                     //0x4
            ULONG Length64;                                                 //0xc
        } Memory64;                                                         //0x4
        struct
        {
            UCHAR Class;                                                    //0x4
            UCHAR Type;                                                     //0x5
            UCHAR Reserved1;                                                //0x6
            UCHAR Reserved2;                                                //0x7
            ULONG IdLowPart;                                                //0x8
            ULONG IdHighPart;                                               //0xc
        } Connection;                                                       //0x4
    } u;                                                                    //0x4
};
#pragma pack(pop)

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_CM_PARTIAL_RESOURCE_LIST
//0x1c bytes (sizeof)
struct _CM_PARTIAL_RESOURCE_LIST
{
    USHORT Version;                                                         //0x0
    USHORT Revision;                                                        //0x2
    ULONG Count;                                                            //0x4
    struct _CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[1];           //0x8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_CM_FULL_RESOURCE_DESCRIPTOR
//0x24 bytes (sizeof)
struct _CM_FULL_RESOURCE_DESCRIPTOR
{
    enum _INTERFACE_TYPE InterfaceType;                                     //0x0
    ULONG BusNumber;                                                        //0x4
    struct _CM_PARTIAL_RESOURCE_LIST PartialResourceList;                   //0x8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_CM_RESOURCE_LIST
//0x28 bytes (sizeof)
struct _CM_RESOURCE_LIST
{
    ULONG Count;                                                            //0x0
    struct _CM_FULL_RESOURCE_DESCRIPTOR List[1];                            //0x4
};

// https://doxygen.reactos.org/de/d2f/xdk_2cmtypes_8h.html#a834798276357b83c750fbb2fe3a3de2c
constexpr uint32_t CmResourceTypeMemory = 3;
constexpr uint32_t CmResourceTypeMemoryLarge = 7;

// https://doxygen.reactos.org/de/d2f/xdk_2cmtypes_8h.html#a1163881ed109930d90b89273a365961b
constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_40 = 0x0200;
constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_48 = 0x0400;
constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_64 = 0x0800;

constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_40_SHIFT = 8;
constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_48_SHIFT = 16;
constexpr uint64_t CM_RESOURCE_MEMORY_LARGE_64_SHIFT = 32;

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_EX_FAST_REF
//0x8 bytes (sizeof)
struct _EX_FAST_REF
{
    union
    {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt:4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_SEP_TOKEN_PRIVILEGES
//0x18 bytes (sizeof)
struct _SEP_TOKEN_PRIVILEGES
{
    ULONGLONG Present;                                                      //0x0
    ULONGLONG Enabled;                                                      //0x8
    ULONGLONG EnabledByDefault;                                             //0x10
};


namespace offsets {

    // https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_EPROCESS
    namespace EProcess {
        // VOID*
        const auto UniqueProcessId = 0x440;
        // _EX_FAST_REF
        const auto Token = 0x4b8;
    }

    // https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_TOKEN
    namespace Token {
        // _SEP_TOKEN_PRIVILEGES
        const auto TokenPrivileges = 0x40;
    }


}

#endif