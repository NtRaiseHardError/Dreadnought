#pragma once
#ifndef __DEFINITIONS_H__
#define __DEFINITIONS_H__

#include <Windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

//
// Generic test for information on any status value.
//

#ifndef NT_INFORMATION
#define NT_INFORMATION(Status) ((((ULONG)(Status)) >> 30) == 1)
#endif

//
// Generic test for warning on any status value.
//

#ifndef NT_WARNING
#define NT_WARNING(Status) ((((ULONG)(Status)) >> 30) == 2)
#endif

//
// Generic test for error on any status value.
//

#ifndef NT_ERROR
#define NT_ERROR(Status) ((((ULONG)(Status)) >> 30) == 3)
#endif

#define ThreadQuerySetWin32StartAddress 9

typedef struct _STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
} STRING;
typedef STRING *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR {
	WORD Flags;
	WORD Length;
	ULONG TimeStamp;
	STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	ULONG MaximumLength;
	ULONG Length;
	ULONG Flags;
	ULONG DebugFlags;
	PVOID ConsoleHandle;
	ULONG ConsoleFlags;
	HANDLE StdInputHandle;
	HANDLE StdOutputHandle;
	HANDLE StdErrorHandle;
	UNICODE_STRING CurrentDirectoryPath;
	HANDLE CurrentDirectoryHandle;
	UNICODE_STRING DllPath;
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
	PVOID Environment;
	ULONG StartingPositionLeft;
	ULONG StartingPositionTop;
	ULONG Width;
	ULONG Height;
	ULONG CharWidth;
	ULONG CharHeight;
	ULONG ConsoleTextAttributes;
	ULONG WindowFlags;
	ULONG ShowWindowFlags;
	UNICODE_STRING WindowTitle;
	UNICODE_STRING DesktopName;
	UNICODE_STRING ShellInfo;
	UNICODE_STRING RuntimeData;
	RTL_DRIVE_LETTER_CURDIR DLCurrentDirectory[0x20];
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef enum _PS_CREATE_STATE {
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName, // Debugger specified
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE;

typedef struct _PS_CREATE_INFO {
	SIZE_T Size;
	PS_CREATE_STATE State;
	union {
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR WriteOutputOnExit : 1;
					UCHAR DetectManifest : 1;
					UCHAR IFEOSkipDebugger : 1;
					UCHAR IFEODoNotPropagateKeyState : 1;
					UCHAR SpareBits1 : 4;
					UCHAR SpareBits2 : 8;
					USHORT ProhibitedImageCharacteristics : 16;
				};
			};
			ACCESS_MASK AdditionalFileAccess;
		} InitState;

		// PsCreateFailOnSectionCreate
		struct {
			HANDLE FileHandle;
		} FailSection;

		// PsCreateFailExeFormat
		struct {
			USHORT DllCharacteristics;
		} ExeFormat;

		// PsCreateFailExeName
		struct {
			HANDLE IFEOKey;
		} ExeName;

		// PsCreateSuccess
		struct {
			union {
				ULONG OutputFlags;
				struct {
					UCHAR ProtectedProcess : 1;
					UCHAR AddressSpaceOverride : 1;
					UCHAR DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR ManifestDetected : 1;
					UCHAR ProtectedProcessLight : 1;
					UCHAR SpareBits1 : 3;
					UCHAR SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE FileHandle;
			HANDLE SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG UserProcessParametersWow64;
			ULONG CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef struct _PS_ATTRIBUTE {
	ULONG Attribute;
	SIZE_T Size;
	union {
		ULONG Value;
		PVOID ValuePtr;
	};
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
	SIZE_T TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef struct _OBJECT_ATTRIBUTES {
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
}  OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

enum PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27
};

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0x0000,
	SystemProcessorInformation = 0x0001,
	SystemPerformanceInformation = 0x0002,
	SystemTimeOfDayInformation = 0x0003,
	SystemPathInformation = 0x0004,
	SystemProcessInformation = 0x0005,
	SystemCallCountInformation = 0x0006,
	SystemDeviceInformation = 0x0007,
	SystemProcessorPerformanceInformation = 0x0008,
	SystemFlagsInformation = 0x0009,
	SystemCallTimeInformation = 0x000A,
	SystemModuleInformation = 0x000B,
	SystemLocksInformation = 0x000C,
	SystemStackTraceInformation = 0x000D,
	SystemPagedPoolInformation = 0x000E,
	SystemNonPagedPoolInformation = 0x000F,
	SystemHandleInformation = 0x0010,
	SystemObjectInformation = 0x0011,
	SystemPageFileInformation = 0x0012,
	SystemVdmInstemulInformation = 0x0013,
	SystemVdmBopInformation = 0x0014,
	SystemFileCacheInformation = 0x0015,
	SystemPoolTagInformation = 0x0016,
	SystemInterruptInformation = 0x0017,
	SystemDpcBehaviorInformation = 0x0018,
	SystemFullMemoryInformation = 0x0019,
	SystemLoadGdiDriverInformation = 0x001A,
	SystemUnloadGdiDriverInformation = 0x001B,
	SystemTimeAdjustmentInformation = 0x001C,
	SystemSummaryMemoryInformation = 0x001D,
	SystemMirrorMemoryInformation = 0x001E,
	SystemPerformanceTraceInformation = 0x001F,
	SystemCrashDumpInformation = 0x0020,
	SystemExceptionInformation = 0x0021,
	SystemCrashDumpStateInformation = 0x0022,
	SystemKernelDebuggerInformation = 0x0023,
	SystemContextSwitchInformation = 0x0024,
	SystemRegistryQuotaInformation = 0x0025,
	SystemExtendServiceTableInformation = 0x0026,
	SystemPrioritySeperation = 0x0027,
	SystemVerifierAddDriverInformation = 0x0028,
	SystemVerifierRemoveDriverInformation = 0x0029,
	SystemProcessorIdleInformation = 0x002A,
	SystemLegacyDriverInformation = 0x002B,
	SystemCurrentTimeZoneInformation = 0x002C,
	SystemLookasideInformation = 0x002D,
	SystemTimeSlipNotification = 0x002E,
	SystemSessionCreate = 0x002F,
	SystemSessionDetach = 0x0030,
	SystemSessionInformation = 0x0031,
	SystemRangeStartInformation = 0x0032,
	SystemVerifierInformation = 0x0033,
	SystemVerifierThunkExtend = 0x0034,
	SystemSessionProcessInformation = 0x0035,
	SystemLoadGdiDriverInSystemSpace = 0x0036,
	SystemNumaProcessorMap = 0x0037,
	SystemPrefetcherInformation = 0x0038,
	SystemExtendedProcessInformation = 0x0039,
	SystemRecommendedSharedDataAlignment = 0x003A,
	SystemComPlusPackage = 0x003B,
	SystemNumaAvailableMemory = 0x003C,
	SystemProcessorPowerInformation = 0x003D,
	SystemEmulationBasicInformation = 0x003E,
	SystemEmulationProcessorInformation = 0x003F,
	SystemExtendedHandleInformation = 0x0040,
	SystemLostDelayedWriteInformation = 0x0041,
	SystemBigPoolInformation = 0x0042,
	SystemSessionPoolTagInformation = 0x0043,
	SystemSessionMappedViewInformation = 0x0044,
	SystemHotpatchInformation = 0x0045,
	SystemObjectSecurityMode = 0x0046,
	SystemWatchdogTimerHandler = 0x0047,
	SystemWatchdogTimerInformation = 0x0048,
	SystemLogicalProcessorInformation = 0x0049,
	SystemWow64SharedInformationObsolete = 0x004A,
	SystemRegisterFirmwareTableInformationHandler = 0x004B,
	SystemFirmwareTableInformation = 0x004C,
	SystemModuleInformationEx = 0x004D,
	SystemVerifierTriageInformation = 0x004E,
	SystemSuperfetchInformation = 0x004F,
	SystemMemoryListInformation = 0x0050,
	SystemFileCacheInformationEx = 0x0051,
	SystemThreadPriorityClientIdInformation = 0x0052,
	SystemProcessorIdleCycleTimeInformation = 0x0053,
	SystemVerifierCancellationInformation = 0x0054,
	SystemProcessorPowerInformationEx = 0x0055,
	SystemRefTraceInformation = 0x0056,
	SystemSpecialPoolInformation = 0x0057,
	SystemProcessIdInformation = 0x0058,
	SystemErrorPortInformation = 0x0059,
	SystemBootEnvironmentInformation = 0x005A,
	SystemHypervisorInformation = 0x005B,
	SystemVerifierInformationEx = 0x005C,
	SystemTimeZoneInformation = 0x005D,
	SystemImageFileExecutionOptionsInformation = 0x005E,
	SystemCoverageInformation = 0x005F,
	SystemPrefetchPatchInformation = 0x0060,
	SystemVerifierFaultsInformation = 0x0061,
	SystemSystemPartitionInformation = 0x0062,
	SystemSystemDiskInformation = 0x0063,
	SystemProcessorPerformanceDistribution = 0x0064,
	SystemNumaProximityNodeInformation = 0x0065,
	SystemDynamicTimeZoneInformation = 0x0066,
	SystemCodeIntegrityInformation = 0x0067,
	SystemProcessorMicrocodeUpdateInformation = 0x0068,
	SystemProcessorBrandString = 0x0069,
	SystemVirtualAddressInformation = 0x006A,
	SystemLogicalProcessorAndGroupInformation = 0x006B,
	SystemProcessorCycleTimeInformation = 0x006C,
	SystemStoreInformation = 0x006D,
	SystemRegistryAppendString = 0x006E,
	SystemAitSamplingValue = 0x006F,
	SystemVhdBootInformation = 0x0070,
	SystemCpuQuotaInformation = 0x0071,
	SystemNativeBasicInformation = 0x0072,
	SystemErrorPortTimeouts = 0x0073,
	SystemLowPriorityIoInformation = 0x0074,
	SystemBootEntropyInformation = 0x0075,
	SystemVerifierCountersInformation = 0x0076,
	SystemPagedPoolInformationEx = 0x0077,
	SystemSystemPtesInformationEx = 0x0078,
	SystemNodeDistanceInformation = 0x0079,
	SystemAcpiAuditInformation = 0x007A,
	SystemBasicPerformanceInformation = 0x007B,
	SystemQueryPerformanceCounterInformation = 0x007C,
	SystemSessionBigPoolInformation = 0x007D,
	SystemBootGraphicsInformation = 0x007E,
	SystemScrubPhysicalMemoryInformation = 0x007F,
	SystemBadPageInformation = 0x0080,
	SystemProcessorProfileControlArea = 0x0081,
	SystemCombinePhysicalMemoryInformation = 0x0082,
	SystemEntropyInterruptTimingInformation = 0x0083,
	SystemConsoleInformation = 0x0084,
	SystemPlatformBinaryInformation = 0x0085,
	SystemThrottleNotificationInformation = 0x0086,
	SystemHypervisorProcessorCountInformation = 0x0087,
	SystemDeviceDataInformation = 0x0088,
	SystemDeviceDataEnumerationInformation = 0x0089,
	SystemMemoryTopologyInformation = 0x008A,
	SystemMemoryChannelInformation = 0x008B,
	SystemBootLogoInformation = 0x008C,
	SystemProcessorPerformanceInformationEx = 0x008D,
	SystemSpare0 = 0x008E,
	SystemSecureBootPolicyInformation = 0x008F,
	SystemPageFileInformationEx = 0x0090,
	SystemSecureBootInformation = 0x0091,
	SystemEntropyInterruptTimingRawInformation = 0x0092,
	SystemPortableWorkspaceEfiLauncherInformation = 0x0093,
	SystemFullProcessInformation = 0x0094,
	MaxSystemInfoClass = 0x0095
} SYSTEM_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT {
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT;

typedef WORD RTL_ATOM, *PRTL_ATOM;

typedef enum _ATOM_INFORMATION_CLASS {
	AtomBasicInformation,
	AtomTableInformation,
} ATOM_INFORMATION_CLASS;

// Undocumented: based on guesswork
typedef struct _THREAD_INFO {
	ULONG   Flags;          // Flags
	ULONG   BufferSize;     // Size of buffer in bytes
	PVOID   lpBuffer;       // Pointer to buffer
	ULONG   Unknown;        // Typically zero
} THREAD_INFO, *PTHREAD_INFO;

// Undocumented: based on guesswork
typedef struct _CREATE_THREAD_INFO {
	ULONG       Length;     // Size of structure in bytes
	THREAD_INFO Client;     // Unknown
	THREAD_INFO TEB;        // User mode stack context?
} CREATE_THREAD_INFO;

typedef struct _CLIENT_ID {
	PVOID UniqueProcess;
	PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _INITIAL_TEB {
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID AllocatedStackBase;
} INITIAL_TEB, *PINITIAL_TEB;

typedef VOID *PIO_APC_ROUTINE;

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _ANSI_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR  Buffer;
} ANSI_STRING, *PANSI_STRING;

#endif // !__DEFINITIONS_H__
