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

// ************************************************************** KTHREAD ********************************************************************

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_DISPATCHER_HEADER
//0x18 bytes (sizeof)
struct _DISPATCHER_HEADER
{
    union
    {
        volatile LONG Lock;                                                 //0x0
        LONG LockNV;                                                        //0x0
        struct
        {
            UCHAR Type;                                                     //0x0
            UCHAR Signalling;                                               //0x1
            UCHAR Size;                                                     //0x2
            UCHAR Reserved1;                                                //0x3
        };
        struct
        {
            UCHAR TimerType;                                                //0x0
            union
            {
                UCHAR TimerControlFlags;                                    //0x1
                struct
                {
                    UCHAR Absolute:1;                                       //0x1
                    UCHAR Wake:1;                                           //0x1
                    UCHAR EncodedTolerableDelay:6;                          //0x1
                };
            };
            UCHAR Hand;                                                     //0x2
            union
            {
                UCHAR TimerMiscFlags;                                       //0x3
                struct
                {
                    UCHAR Index:6;                                          //0x3
                    UCHAR Inserted:1;                                       //0x3
                    volatile UCHAR Expired:1;                               //0x3
                };
            };
        };
        struct
        {
            UCHAR Timer2Type;                                               //0x0
            union
            {
                UCHAR Timer2Flags;                                          //0x1
                struct
                {
                    UCHAR Timer2Inserted:1;                                 //0x1
                    UCHAR Timer2Expiring:1;                                 //0x1
                    UCHAR Timer2CancelPending:1;                            //0x1
                    UCHAR Timer2SetPending:1;                               //0x1
                    UCHAR Timer2Running:1;                                  //0x1
                    UCHAR Timer2Disabled:1;                                 //0x1
                    UCHAR Timer2ReservedFlags:2;                            //0x1
                };
            };
            UCHAR Timer2ComponentId;                                        //0x2
            UCHAR Timer2RelativeId;                                         //0x3
        };
        struct
        {
            UCHAR QueueType;                                                //0x0
            union
            {
                UCHAR QueueControlFlags;                                    //0x1
                struct
                {
                    UCHAR Abandoned:1;                                      //0x1
                    UCHAR DisableIncrement:1;                               //0x1
                    UCHAR QueueReservedControlFlags:6;                      //0x1
                };
            };
            UCHAR QueueSize;                                                //0x2
            UCHAR QueueReserved;                                            //0x3
        };
        struct
        {
            UCHAR ThreadType;                                               //0x0
            UCHAR ThreadReserved;                                           //0x1
            union
            {
                UCHAR ThreadControlFlags;                                   //0x2
                struct
                {
                    UCHAR CycleProfiling:1;                                 //0x2
                    UCHAR CounterProfiling:1;                               //0x2
                    UCHAR GroupScheduling:1;                                //0x2
                    UCHAR AffinitySet:1;                                    //0x2
                    UCHAR Tagged:1;                                         //0x2
                    UCHAR EnergyProfiling:1;                                //0x2
                    UCHAR SchedulerAssist:1;                                //0x2
                    UCHAR ThreadReservedControlFlags:1;                     //0x2
                };
            };
            union
            {
                UCHAR DebugActive;                                          //0x3
                struct
                {
                    UCHAR ActiveDR7:1;                                      //0x3
                    UCHAR Instrumented:1;                                   //0x3
                    UCHAR Minimal:1;                                        //0x3
                    UCHAR Reserved4:2;                                      //0x3
                    UCHAR AltSyscall:1;                                     //0x3
                    UCHAR UmsScheduled:1;                                   //0x3
                    UCHAR UmsPrimary:1;                                     //0x3
                };
            };
        };
        struct
        {
            UCHAR MutantType;                                               //0x0
            UCHAR MutantSize;                                               //0x1
            UCHAR DpcActive;                                                //0x2
            UCHAR MutantReserved;                                           //0x3
        };
    };
    LONG SignalState;                                                       //0x4
    struct _LIST_ENTRY WaitListHead;                                        //0x8
};

//https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KWAIT_STATUS_REGISTER
//0x1 bytes (sizeof)
union _KWAIT_STATUS_REGISTER
{
    UCHAR Flags;                                                            //0x0
    UCHAR State:3;                                                          //0x0
    UCHAR Affinity:1;                                                       //0x0
    UCHAR Priority:1;                                                       //0x0
    UCHAR Apc:1;                                                            //0x0
    UCHAR UserApc:1;                                                        //0x0
    UCHAR Alert:1;                                                          //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KAPC_STATE
//0x30 bytes (sizeof)
struct _KAPC_STATE
{
    struct _LIST_ENTRY ApcListHead[2];                                      //0x0
    struct _KPROCESS* Process;                                              //0x20
    union
    {
        UCHAR InProgressFlags;                                              //0x28
        struct
        {
            UCHAR KernelApcInProgress:1;                                    //0x28
            UCHAR SpecialApcInProgress:1;                                   //0x28
        };
    };
    UCHAR KernelApcPending;                                                 //0x29
    union
    {
        UCHAR UserApcPendingAll;                                            //0x2a
        struct
        {
            UCHAR SpecialUserApcPending:1;                                  //0x2a
            UCHAR UserApcPending:1;                                         //0x2a
        };
    };
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KTIMER
//0x40 bytes (sizeof)
struct _KTIMER
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    union _ULARGE_INTEGER DueTime;                                          //0x18
    struct _LIST_ENTRY TimerListEntry;                                      //0x20
    struct _KDPC* Dpc;                                                      //0x30
    USHORT Processor;                                                       //0x38
    USHORT TimerType;                                                       //0x3a
    ULONG Period;                                                           //0x3c
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KAPC
//0x58 bytes (sizeof)
struct _KAPC
{
    UCHAR Type;                                                             //0x0
    UCHAR SpareByte0;                                                       //0x1
    UCHAR Size;                                                             //0x2
    UCHAR SpareByte1;                                                       //0x3
    ULONG SpareLong0;                                                       //0x4
    struct _KTHREAD* Thread;                                                //0x8
    struct _LIST_ENTRY ApcListEntry;                                        //0x10
    VOID* Reserved[3];                                                      //0x20
    VOID* NormalContext;                                                    //0x38
    VOID* SystemArgument1;                                                  //0x40
    VOID* SystemArgument2;                                                  //0x48
    CHAR ApcStateIndex;                                                     //0x50
    CHAR ApcMode;                                                           //0x51
    UCHAR Inserted;                                                         //0x52
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KWAIT_BLOCK
//0x30 bytes (sizeof)
struct _KWAIT_BLOCK
{
    struct _LIST_ENTRY WaitListEntry;                                       //0x0
    UCHAR WaitType;                                                         //0x10
    volatile UCHAR BlockState;                                              //0x11
    USHORT WaitKey;                                                         //0x12
    LONG SpareLong;                                                         //0x14
    union
    {
        struct _KTHREAD* Thread;                                            //0x18
        struct _KQUEUE* NotificationQueue;                                  //0x18
    };
    VOID* Object;                                                           //0x20
    VOID* SparePtr;                                                         //0x28
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KEVENT
//0x18 bytes (sizeof)
struct _KEVENT
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KTHREAD
//0x430 bytes (sizeof)
struct _KTHREAD
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    VOID* SListFaultAddress;                                                //0x18
    ULONGLONG QuantumTarget;                                                //0x20
    VOID* InitialStack;                                                     //0x28
    VOID* volatile StackLimit;                                              //0x30
    VOID* StackBase;                                                        //0x38
    ULONGLONG ThreadLock;                                                   //0x40
    volatile ULONGLONG CycleTime;                                           //0x48
    ULONG CurrentRunTime;                                                   //0x50
    ULONG ExpectedRunTime;                                                  //0x54
    VOID* KernelStack;                                                      //0x58
    struct _XSAVE_FORMAT* StateSaveArea;                                    //0x60
    struct _KSCHEDULING_GROUP* volatile SchedulingGroup;                    //0x68
    union _KWAIT_STATUS_REGISTER WaitRegister;                              //0x70
    volatile UCHAR Running;                                                 //0x71
    UCHAR Alerted[2];                                                       //0x72
    union
    {
        struct
        {
            ULONG AutoBoostActive:1;                                        //0x74
            ULONG ReadyTransition:1;                                        //0x74
            ULONG WaitNext:1;                                               //0x74
            ULONG SystemAffinityActive:1;                                   //0x74
            ULONG Alertable:1;                                              //0x74
            ULONG UserStackWalkActive:1;                                    //0x74
            ULONG ApcInterruptRequest:1;                                    //0x74
            ULONG QuantumEndMigrate:1;                                      //0x74
            ULONG UmsDirectedSwitchEnable:1;                                //0x74
            ULONG TimerActive:1;                                            //0x74
            ULONG SystemThread:1;                                           //0x74
            ULONG ProcessDetachActive:1;                                    //0x74
            ULONG CalloutActive:1;                                          //0x74
            ULONG ScbReadyQueue:1;                                          //0x74
            ULONG ApcQueueable:1;                                           //0x74
            ULONG ReservedStackInUse:1;                                     //0x74
            ULONG UmsPerformingSyscall:1;                                   //0x74
            ULONG TimerSuspended:1;                                         //0x74
            ULONG SuspendedWaitMode:1;                                      //0x74
            ULONG SuspendSchedulerApcWait:1;                                //0x74
            ULONG CetUserShadowStack:1;                                     //0x74
            ULONG BypassProcessFreeze:1;                                    //0x74
            ULONG Reserved:10;                                              //0x74
        };
        LONG MiscFlags;                                                     //0x74
    };
    union
    {
        struct
        {
            ULONG ThreadFlagsSpare:2;                                       //0x78
            ULONG AutoAlignment:1;                                          //0x78
            ULONG DisableBoost:1;                                           //0x78
            ULONG AlertedByThreadId:1;                                      //0x78
            ULONG QuantumDonation:1;                                        //0x78
            ULONG EnableStackSwap:1;                                        //0x78
            ULONG GuiThread:1;                                              //0x78
            ULONG DisableQuantum:1;                                         //0x78
            ULONG ChargeOnlySchedulingGroup:1;                              //0x78
            ULONG DeferPreemption:1;                                        //0x78
            ULONG QueueDeferPreemption:1;                                   //0x78
            ULONG ForceDeferSchedule:1;                                     //0x78
            ULONG SharedReadyQueueAffinity:1;                               //0x78
            ULONG FreezeCount:1;                                            //0x78
            ULONG TerminationApcRequest:1;                                  //0x78
            ULONG AutoBoostEntriesExhausted:1;                              //0x78
            ULONG KernelStackResident:1;                                    //0x78
            ULONG TerminateRequestReason:2;                                 //0x78
            ULONG ProcessStackCountDecremented:1;                           //0x78
            ULONG RestrictedGuiThread:1;                                    //0x78
            ULONG VpBackingThread:1;                                        //0x78
            ULONG ThreadFlagsSpare2:1;                                      //0x78
            ULONG EtwStackTraceApcInserted:8;                               //0x78
        };
        volatile LONG ThreadFlags;                                          //0x78
    };
    volatile UCHAR Tag;                                                     //0x7c
    UCHAR SystemHeteroCpuPolicy;                                            //0x7d
    UCHAR UserHeteroCpuPolicy:7;                                            //0x7e
    UCHAR ExplicitSystemHeteroCpuPolicy:1;                                  //0x7e
    union
    {
        struct
        {
            UCHAR RunningNonRetpolineCode:1;                                //0x7f
            UCHAR SpecCtrlSpare:7;                                          //0x7f
        };
        UCHAR SpecCtrl;                                                     //0x7f
    };
    ULONG SystemCallNumber;                                                 //0x80
    ULONG ReadyTime;                                                        //0x84
    VOID* FirstArgument;                                                    //0x88
    struct _KTRAP_FRAME* TrapFrame;                                         //0x90
    union
    {
        struct _KAPC_STATE ApcState;                                        //0x98
        struct
        {
            UCHAR ApcStateFill[43];                                         //0x98
            CHAR Priority;                                                  //0xc3
            ULONG UserIdealProcessor;                                       //0xc4
        };
    };
    volatile LONGLONG WaitStatus;                                           //0xc8
    struct _KWAIT_BLOCK* WaitBlockList;                                     //0xd0
    union
    {
        struct _LIST_ENTRY WaitListEntry;                                   //0xd8
        struct _SINGLE_LIST_ENTRY SwapListEntry;                            //0xd8
    };
    struct _DISPATCHER_HEADER* volatile Queue;                              //0xe8
    VOID* Teb;                                                              //0xf0
    ULONGLONG RelativeTimerBias;                                            //0xf8
    struct _KTIMER Timer;                                                   //0x100
    union
    {
        struct _KWAIT_BLOCK WaitBlock[4];                                   //0x140
        struct
        {
            UCHAR WaitBlockFill4[20];                                       //0x140
            ULONG ContextSwitches;                                          //0x154
        };
        struct
        {
            UCHAR WaitBlockFill5[68];                                       //0x140
            volatile UCHAR State;                                           //0x184
            CHAR Spare13;                                                   //0x185
            UCHAR WaitIrql;                                                 //0x186
            CHAR WaitMode;                                                  //0x187
        };
        struct
        {
            UCHAR WaitBlockFill6[116];                                      //0x140
            ULONG WaitTime;                                                 //0x1b4
        };
        struct
        {
            UCHAR WaitBlockFill7[164];                                      //0x140
            union
            {
                struct
                {
                    SHORT KernelApcDisable;                                 //0x1e4
                    SHORT SpecialApcDisable;                                //0x1e6
                };
                ULONG CombinedApcDisable;                                   //0x1e4
            };
        };
        struct
        {
            UCHAR WaitBlockFill8[40];                                       //0x140
            struct _KTHREAD_COUNTERS* ThreadCounters;                       //0x168
        };
        struct
        {
            UCHAR WaitBlockFill9[88];                                       //0x140
            struct _XSTATE_SAVE* XStateSave;                                //0x198
        };
        struct
        {
            UCHAR WaitBlockFill10[136];                                     //0x140
            VOID* volatile Win32Thread;                                     //0x1c8
        };
        struct
        {
            UCHAR WaitBlockFill11[176];                                     //0x140
            struct _UMS_CONTROL_BLOCK* Ucb;                                 //0x1f0
            struct _KUMS_CONTEXT_HEADER* volatile Uch;                      //0x1f8
        };
    };
    union
    {
        volatile LONG ThreadFlags2;                                         //0x200
        struct
        {
            ULONG BamQosLevel:8;                                            //0x200
            ULONG ThreadFlags2Reserved:24;                                  //0x200
        };
    };
    ULONG Spare21;                                                          //0x204
    struct _LIST_ENTRY QueueListEntry;                                      //0x208
    union
    {
        volatile ULONG NextProcessor;                                       //0x218
        struct
        {
            ULONG NextProcessorNumber:31;                                   //0x218
            ULONG SharedReadyQueue:1;                                       //0x218
        };
    };
    LONG QueuePriority;                                                     //0x21c
    struct _KPROCESS* Process;                                              //0x220
    union
    {
        struct _GROUP_AFFINITY UserAffinity;                                //0x228
        struct
        {
            UCHAR UserAffinityFill[10];                                     //0x228
            CHAR PreviousMode;                                              //0x232
            CHAR BasePriority;                                              //0x233
            union
            {
                CHAR PriorityDecrement;                                     //0x234
                struct
                {
                    UCHAR ForegroundBoost:4;                                //0x234
                    UCHAR UnusualBoost:4;                                   //0x234
                };
            };
            UCHAR Preempted;                                                //0x235
            UCHAR AdjustReason;                                             //0x236
            CHAR AdjustIncrement;                                           //0x237
        };
    };
    ULONGLONG AffinityVersion;                                              //0x238
    union
    {
        struct _GROUP_AFFINITY Affinity;                                    //0x240
        struct
        {
            UCHAR AffinityFill[10];                                         //0x240
            UCHAR ApcStateIndex;                                            //0x24a
            UCHAR WaitBlockCount;                                           //0x24b
            ULONG IdealProcessor;                                           //0x24c
        };
    };
    ULONGLONG NpxState;                                                     //0x250
    union
    {
        struct _KAPC_STATE SavedApcState;                                   //0x258
        struct
        {
            UCHAR SavedApcStateFill[43];                                    //0x258
            UCHAR WaitReason;                                               //0x283
            CHAR SuspendCount;                                              //0x284
            CHAR Saturation;                                                //0x285
            USHORT SListFaultCount;                                         //0x286
        };
    };
    union
    {
        struct _KAPC SchedulerApc;                                          //0x288
        struct
        {
            UCHAR SchedulerApcFill0[1];                                     //0x288
            UCHAR ResourceIndex;                                            //0x289
        };
        struct
        {
            UCHAR SchedulerApcFill1[3];                                     //0x288
            UCHAR QuantumReset;                                             //0x28b
        };
        struct
        {
            UCHAR SchedulerApcFill2[4];                                     //0x288
            ULONG KernelTime;                                               //0x28c
        };
        struct
        {
            UCHAR SchedulerApcFill3[64];                                    //0x288
            struct _KPRCB* volatile WaitPrcb;                               //0x2c8
        };
        struct
        {
            UCHAR SchedulerApcFill4[72];                                    //0x288
            VOID* LegoData;                                                 //0x2d0
        };
        struct
        {
            UCHAR SchedulerApcFill5[83];                                    //0x288
            UCHAR CallbackNestingLevel;                                     //0x2db
            ULONG UserTime;                                                 //0x2dc
        };
    };
    struct _KEVENT SuspendEvent;                                            //0x2e0
    struct _LIST_ENTRY ThreadListEntry;                                     //0x2f8
    struct _LIST_ENTRY MutantListHead;                                      //0x308
    UCHAR AbEntrySummary;                                                   //0x318
    UCHAR AbWaitEntryCount;                                                 //0x319
    UCHAR AbAllocationRegionCount;                                          //0x31a
    CHAR SystemPriority;                                                    //0x31b
    ULONG SecureThreadCookie;                                               //0x31c
    struct _KLOCK_ENTRY* LockEntries;                                       //0x320
    struct _SINGLE_LIST_ENTRY PropagateBoostsEntry;                         //0x328
    struct _SINGLE_LIST_ENTRY IoSelfBoostsEntry;                            //0x330
    UCHAR PriorityFloorCounts[16];                                          //0x338
    UCHAR PriorityFloorCountsReserved[16];                                  //0x348
    ULONG PriorityFloorSummary;                                             //0x358
    volatile LONG AbCompletedIoBoostCount;                                  //0x35c
    volatile LONG AbCompletedIoQoSBoostCount;                               //0x360
    volatile SHORT KeReferenceCount;                                        //0x364
    UCHAR AbOrphanedEntrySummary;                                           //0x366
    UCHAR AbOwnedEntryCount;                                                //0x367
    ULONG ForegroundLossTime;                                               //0x368
    union
    {
        struct _LIST_ENTRY GlobalForegroundListEntry;                       //0x370
        struct
        {
            struct _SINGLE_LIST_ENTRY ForegroundDpcStackListEntry;          //0x370
            ULONGLONG InGlobalForegroundList;                               //0x378
        };
    };
    LONGLONG ReadOperationCount;                                            //0x380
    LONGLONG WriteOperationCount;                                           //0x388
    LONGLONG OtherOperationCount;                                           //0x390
    LONGLONG ReadTransferCount;                                             //0x398
    LONGLONG WriteTransferCount;                                            //0x3a0
    LONGLONG OtherTransferCount;                                            //0x3a8
    struct _KSCB* QueuedScb;                                                //0x3b0
    volatile ULONG ThreadTimerDelay;                                        //0x3b8
    union
    {
        volatile LONG ThreadFlags3;                                         //0x3bc
        struct
        {
            ULONG ThreadFlags3Reserved:8;                                   //0x3bc
            ULONG PpmPolicy:2;                                              //0x3bc
            ULONG ThreadFlags3Reserved2:22;                                 //0x3bc
        };
    };
    ULONGLONG TracingPrivate[1];                                            //0x3c0
    VOID* SchedulerAssist;                                                  //0x3c8
    VOID* volatile AbWaitObject;                                            //0x3d0
    ULONG ReservedPreviousReadyTimeValue;                                   //0x3d8
    ULONGLONG KernelWaitTime;                                               //0x3e0
    ULONGLONG UserWaitTime;                                                 //0x3e8
    union
    {
        struct _LIST_ENTRY GlobalUpdateVpThreadPriorityListEntry;           //0x3f0
        struct
        {
            struct _SINGLE_LIST_ENTRY UpdateVpThreadPriorityDpcStackListEntry; //0x3f0
            ULONGLONG InGlobalUpdateVpThreadPriorityList;                   //0x3f8
        };
    };
    LONG SchedulerAssistPriorityFloor;                                      //0x400
    ULONG Spare28;                                                          //0x404
    ULONGLONG EndPadding[5];                                                //0x408
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_EX_PUSH_LOCK
//0x8 bytes (sizeof)
struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked:1;                                             //0x0
            ULONGLONG Waiting:1;                                            //0x0
            ULONGLONG Waking:1;                                             //0x0
            ULONGLONG MultipleShared:1;                                     //0x0
            ULONGLONG Shared:60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_EX_RUNDOWN_REF
//0x8 bytes (sizeof)
struct _EX_RUNDOWN_REF
{
    union
    {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

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

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_RTL_AVL_TREE
//0x8 bytes (sizeof)
struct _RTL_AVL_TREE
{
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_SE_AUDIT_PROCESS_CREATION_INFO
//0x8 bytes (sizeof)
struct _SE_AUDIT_PROCESS_CREATION_INFO
{
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_MMSUPPORT_FLAGS
//0x4 bytes (sizeof)
struct _MMSUPPORT_FLAGS
{
    union
    {
        struct
        {
            UCHAR WorkingSetType:3;                                         //0x0
            UCHAR Reserved0:3;                                              //0x0
            UCHAR MaximumWorkingSetHard:1;                                  //0x0
            UCHAR MinimumWorkingSetHard:1;                                  //0x0
            UCHAR SessionMaster:1;                                          //0x1
            UCHAR TrimmerState:2;                                           //0x1
            UCHAR Reserved:1;                                               //0x1
            UCHAR PageStealers:4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union
    {
        struct
        {
            UCHAR WsleDeleted:1;                                            //0x3
            UCHAR SvmEnabled:1;                                             //0x3
            UCHAR ForceAge:1;                                               //0x3
            UCHAR ForceTrim:1;                                              //0x3
            UCHAR NewMaximum:1;                                             //0x3
            UCHAR CommitReleaseState:2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_MMSUPPORT_INSTANCE
//0xc0 bytes (sizeof)
struct _MMSUPPORT_INSTANCE
{
    ULONG NextPageColor;                                                    //0x0
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_MMSUPPORT_SHARED
//0x80 bytes (sizeof)
struct _MMSUPPORT_SHARED
{
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG WorkingSetCoreLock;                                           //0x40
    VOID* ShadowMapping;                                                    //0x48
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_MMSUPPORT_FULL
//0x140 bytes (sizeof)
struct _MMSUPPORT_FULL
{
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_ALPC_PROCESS_CONTEXT
//0x20 bytes (sizeof)
struct _ALPC_PROCESS_CONTEXT
{
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_PS_PROCESS_WAKE_INFORMATION
//0x30 bytes (sizeof)
struct _PS_PROCESS_WAKE_INFORMATION
{
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
//0x10 bytes (sizeof)
struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES
{
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_PS_INTERLOCKED_TIMER_DELAY_VALUES
//0x8 bytes (sizeof)
union _PS_INTERLOCKED_TIMER_DELAY_VALUES
{
    ULONGLONG DelayMs:30;                                                   //0x0
    ULONGLONG CoalescingWindowMs:30;                                        //0x0
    ULONGLONG Reserved:1;                                                   //0x0
    ULONGLONG NewTimerWheel:1;                                              //0x0
    ULONGLONG Retry:1;                                                      //0x0
    ULONGLONG Locked:1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KSTACK_COUNT
//0x4 bytes (sizeof)
union _KSTACK_COUNT
{
    LONG Value;                                                             //0x0
    ULONG State:3;                                                          //0x0
    ULONG StackCount:29;                                                    //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KAFFINITY_EX
//0xa8 bytes (sizeof)
struct _KAFFINITY_EX
{
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KEXECUTE_OPTIONS
//0x1 bytes (sizeof)
union _KEXECUTE_OPTIONS
{
    UCHAR ExecuteDisable:1;                                                 //0x0
    UCHAR ExecuteEnable:1;                                                  //0x0
    UCHAR DisableThunkEmulation:1;                                          //0x0
    UCHAR Permanent:1;                                                      //0x0
    UCHAR ExecuteDispatchEnable:1;                                          //0x0
    UCHAR ImageDispatchEnable:1;                                            //0x0
    UCHAR DisableExceptionChainValidation:1;                                //0x0
    UCHAR Spare:1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_KPROCESS
//0x438 bytes (sizeof)
struct _KPROCESS
{
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    ULONGLONG AffinityPadding[12];                                          //0xf8
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
    ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
    union
    {
        struct
        {
            ULONG AutoAlignment:1;                                          //0x278
            ULONG DisableBoost:1;                                           //0x278
            ULONG DisableQuantum:1;                                         //0x278
            ULONG DeepFreeze:1;                                             //0x278
            ULONG TimerVirtualization:1;                                    //0x278
            ULONG CheckStackExtents:1;                                      //0x278
            ULONG CacheIsolationEnabled:1;                                  //0x278
            ULONG PpmPolicy:3;                                              //0x278
            ULONG VaSpaceDeleted:1;                                         //0x278
            ULONG ReservedFlags:21;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    union _KEXECUTE_OPTIONS Flags;                                          //0x283
    USHORT ThreadSeed[20];                                                  //0x284
    USHORT ThreadSeedPadding[12];                                           //0x2ac
    USHORT IdealProcessor[20];                                              //0x2c4
    USHORT IdealProcessorPadding[12];                                       //0x2ec
    USHORT IdealNode[20];                                                   //0x304
    USHORT IdealNodePadding[12];                                            //0x32c
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    volatile _KSTACK_COUNT StackCount;                                      //0x348
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union
    {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct
        {
            ULONGLONG SecureProcess:1;                                      //0x3e0
            ULONGLONG Unused:1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG EndPadding[8];                                                //0x3f8
};

// https://www.vergiliusproject.com/kernels/x64/Windows%2010%20|%202016/2110%2021H2%20(November%202021%20Update)/_EPROCESS
//0xa40 bytes (sizeof)
struct _EPROCESS
{
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union
    {
        ULONG Flags2;                                                       //0x460
        struct
        {
            ULONG JobNotReallyActive:1;                                     //0x460
            ULONG AccountingFolded:1;                                       //0x460
            ULONG NewProcessReported:1;                                     //0x460
            ULONG ExitProcessReported:1;                                    //0x460
            ULONG ReportCommitChanges:1;                                    //0x460
            ULONG LastReportMemory:1;                                       //0x460
            ULONG ForceWakeCharge:1;                                        //0x460
            ULONG CrossSessionCreate:1;                                     //0x460
            ULONG NeedsHandleRundown:1;                                     //0x460
            ULONG RefTraceEnabled:1;                                        //0x460
            ULONG PicoCreated:1;                                            //0x460
            ULONG EmptyJobEvaluated:1;                                      //0x460
            ULONG DefaultPagePriority:3;                                    //0x460
            ULONG PrimaryTokenFrozen:1;                                     //0x460
            ULONG ProcessVerifierTarget:1;                                  //0x460
            ULONG RestrictSetThreadContext:1;                               //0x460
            ULONG AffinityPermanent:1;                                      //0x460
            ULONG AffinityUpdateEnable:1;                                   //0x460
            ULONG PropagateNode:1;                                          //0x460
            ULONG ExplicitAffinity:1;                                       //0x460
            ULONG ProcessExecutionState:2;                                  //0x460
            ULONG EnableReadVmLogging:1;                                    //0x460
            ULONG EnableWriteVmLogging:1;                                   //0x460
            ULONG FatalAccessTerminationRequested:1;                        //0x460
            ULONG DisableSystemAllowedCpuSet:1;                             //0x460
            ULONG ProcessStateChangeRequest:2;                              //0x460
            ULONG ProcessStateChangeInProgress:1;                           //0x460
            ULONG InPrivate:1;                                              //0x460
        };
    };
    union
    {
        ULONG Flags;                                                        //0x464
        struct
        {
            ULONG CreateReported:1;                                         //0x464
            ULONG NoDebugInherit:1;                                         //0x464
            ULONG ProcessExiting:1;                                         //0x464
            ULONG ProcessDelete:1;                                          //0x464
            ULONG ManageExecutableMemoryWrites:1;                           //0x464
            ULONG VmDeleted:1;                                              //0x464
            ULONG OutswapEnabled:1;                                         //0x464
            ULONG Outswapped:1;                                             //0x464
            ULONG FailFastOnCommitFail:1;                                   //0x464
            ULONG Wow64VaSpace4Gb:1;                                        //0x464
            ULONG AddressSpaceInitialized:2;                                //0x464
            ULONG SetTimerResolution:1;                                     //0x464
            ULONG BreakOnTermination:1;                                     //0x464
            ULONG DeprioritizeViews:1;                                      //0x464
            ULONG WriteWatch:1;                                             //0x464
            ULONG ProcessInSession:1;                                       //0x464
            ULONG OverrideAddressSpace:1;                                   //0x464
            ULONG HasAddressSpace:1;                                        //0x464
            ULONG LaunchPrefetched:1;                                       //0x464
            ULONG Background:1;                                             //0x464
            ULONG VmTopDown:1;                                              //0x464
            ULONG ImageNotifyDone:1;                                        //0x464
            ULONG PdeUpdateNeeded:1;                                        //0x464
            ULONG VdmAllowed:1;                                             //0x464
            ULONG ProcessRundown:1;                                         //0x464
            ULONG ProcessInserted:1;                                        //0x464
            ULONG DefaultIoPriority:3;                                      //0x464
            ULONG ProcessSelfDelete:1;                                      //0x464
            ULONG SetTimerResolutionLink:1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union
    {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState:3;                                     //0x4b0
    };
    struct _EX_FAST_REF Token;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE CloneRoot;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;                                                        //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    struct _EX_FAST_REF PrefetchTrace;                                      //0x600
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL Vm;                                              //0x680
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount:3;                                                      //0x87b
    UCHAR GhostCount:3;                                                     //0x87b
    UCHAR PrefilterException:1;                                             //0x87b
    union
    {
        ULONG Flags3;                                                       //0x87c
        struct
        {
            ULONG Minimal:1;                                                //0x87c
            ULONG ReplacingPageRoot:1;                                      //0x87c
            ULONG Crashed:1;                                                //0x87c
            ULONG JobVadsAreTracked:1;                                      //0x87c
            ULONG VadTrackingDisabled:1;                                    //0x87c
            ULONG AuxiliaryProcess:1;                                       //0x87c
            ULONG SubsystemProcess:1;                                       //0x87c
            ULONG IndirectCpuSets:1;                                        //0x87c
            ULONG RelinquishedCommit:1;                                     //0x87c
            ULONG HighGraphicsPriority:1;                                   //0x87c
            ULONG CommitFailLogged:1;                                       //0x87c
            ULONG ReserveFailLogged:1;                                      //0x87c
            ULONG SystemProcess:1;                                          //0x87c
            ULONG HideImageBaseAddresses:1;                                 //0x87c
            ULONG AddressPolicyFrozen:1;                                    //0x87c
            ULONG ProcessFirstResume:1;                                     //0x87c
            ULONG ForegroundExternal:1;                                     //0x87c
            ULONG ForegroundSystem:1;                                       //0x87c
            ULONG HighMemoryPriority:1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging:1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging:1;                       //0x87c
            ULONG SecurityDomainChanged:1;                                  //0x87c
            ULONG SecurityFreezeComplete:1;                                 //0x87c
            ULONG VmProcessorHost:1;                                        //0x87c
            ULONG VmProcessorHostTransition:1;                              //0x87c
            ULONG AltSyscall:1;                                             //0x87c
            ULONG TimerResolutionIgnore:1;                                  //0x87c
            ULONG DisallowUserTerminate:1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime:61;                                        //0x920
    ULONGLONG LastAppState:3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union
    {
        struct
        {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct
        {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;     //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union
    {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union
    {
        ULONG MitigationFlags;                                              //0x9d0
        struct
        {
            ULONG ControlFlowGuardEnabled:1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled:1;               //0x9d0
            ULONG ControlFlowGuardStrict:1;                                 //0x9d0
            ULONG DisallowStrippedImages:1;                                 //0x9d0
            ULONG ForceRelocateImages:1;                                    //0x9d0
            ULONG HighEntropyASLREnabled:1;                                 //0x9d0
            ULONG StackRandomizationDisabled:1;                             //0x9d0
            ULONG ExtensionPointDisable:1;                                  //0x9d0
            ULONG DisableDynamicCode:1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut:1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade:1;                 //0x9d0
            ULONG AuditDisableDynamicCode:1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls:1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls:1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs:1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs:1;                                //0x9d0
            ULONG DisableNonSystemFonts:1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading:1;                              //0x9d0
            ULONG PreferSystem32Images:1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap:1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap:1;                            //0x9d0
            ULONG ProhibitLowILImageMap:1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap:1;                             //0x9d0
            ULONG SignatureMitigationOptIn:1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries:1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore:1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled:1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity:1;                         //0x9d0
            ULONG EnableModuleTamperingProtection:1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit:1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction:1;                       //0x9d0
            ULONG IsolateSecurityDomain:1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter:1;                              //0x9d4
            ULONG AuditExportAddressFilter:1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus:1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus:1;                           //0x9d4
            ULONG EnableRopStackPivot:1;                                    //0x9d4
            ULONG AuditRopStackPivot:1;                                     //0x9d4
            ULONG EnableRopCallerCheck:1;                                   //0x9d4
            ULONG AuditRopCallerCheck:1;                                    //0x9d4
            ULONG EnableRopSimExec:1;                                       //0x9d4
            ULONG AuditRopSimExec:1;                                        //0x9d4
            ULONG EnableImportAddressFilter:1;                              //0x9d4
            ULONG AuditImportAddressFilter:1;                               //0x9d4
            ULONG DisablePageCombine:1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable:1;                          //0x9d4
            ULONG CetUserShadowStacks:1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks:1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged:1;                         //0x9d4
            ULONG UserCetSetContextIpValidation:1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation:1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged:1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode:1;                          //0x9d4
            ULONG BlockNonCetBinaries:1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont:1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries:1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged:1;                         //0x9d4
            ULONG Reserved1:1;                                              //0x9d4
            ULONG Reserved2:1;                                              //0x9d4
            ULONG Reserved3:1;                                              //0x9d4
            ULONG Reserved4:1;                                              //0x9d4
            ULONG Reserved5:1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly:1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode:1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
};

#endif