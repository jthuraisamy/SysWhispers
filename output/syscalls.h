#pragma once

#include <Windows.h>

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE
{
	ULONG64        Version;
	UNICODE_STRING Name;
} TOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE
{
	PVOID pValue;
	ULONG ValueLength;
} TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE, *PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE;

typedef struct _IO_STATUS_BLOCK
{
	union
	{
		NTSTATUS Status;
		VOID*    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _CLIENT_ID
{
	void* UniqueProcess;
	void* UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _PLUGPLAY_EVENT_CATEGORY
{
	HardwareProfileChangeEvent,
	TargetDeviceChangeEvent,
	DeviceClassChangeEvent,
	CustomDeviceEvent,
	DeviceInstallEvent,
	DeviceArrivalEvent,
	PowerEvent,
	VetoEvent,
	BlockedDriverEvent,
	InvalidIDEvent,
	MaxPlugEventCategory
} PLUGPLAY_EVENT_CATEGORY, *PPLUGPLAY_EVENT_CATEGORY;

typedef enum _PNP_VETO_TYPE
{
	PNP_VetoTypeUnknown, // unspecified
	PNP_VetoLegacyDevice, // instance path
	PNP_VetoPendingClose, // instance path
	PNP_VetoWindowsApp, // module
	PNP_VetoWindowsService, // service
	PNP_VetoOutstandingOpen, // instance path
	PNP_VetoDevice, // instance path
	PNP_VetoDriver, // driver service name
	PNP_VetoIllegalDeviceRequest, // instance path
	PNP_VetoInsufficientPower, // unspecified
	PNP_VetoNonDisableable, // instance path
	PNP_VetoLegacyDriver, // service
	PNP_VetoInsufficientRights  // unspecified
} PNP_VETO_TYPE, *PPNP_VETO_TYPE;

typedef struct _TOKEN_SECURITY_ATTRIBUTE_V1
{
	UNICODE_STRING Name;
	USHORT         ValueType;
	USHORT         Reserved;
	ULONG          Flags;
	ULONG          ValueCount;
	union
	{
		PLONG64                                      pInt64;
		PULONG64                                     pUint64;
		PUNICODE_STRING                              pString;
		PTOKEN_SECURITY_ATTRIBUTE_FQBN_VALUE         pFqbn;
		PTOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE pOctetString;
	} Values;
} TOKEN_SECURITY_ATTRIBUTE_V1, *PTOKEN_SECURITY_ATTRIBUTE_V1;

typedef struct _WNF_STATE_NAME
{
	ULONG Data[2];
} WNF_STATE_NAME, *PWNF_STATE_NAME;

typedef VOID(KNORMAL_ROUTINE) (
	IN PVOID NormalContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2);

typedef struct _PS_ATTRIBUTE
{
	ULONG  Attribute;
	SIZE_T Size;
	union
	{
		ULONG Value;
		PVOID ValuePtr;
	} u1;
	PSIZE_T ReturnLength;
} PS_ATTRIBUTE, *PPS_ATTRIBUTE;

typedef enum _PS_CREATE_STATE
{
	PsCreateInitialState,
	PsCreateFailOnFileOpen,
	PsCreateFailOnSectionCreate,
	PsCreateFailExeFormat,
	PsCreateFailMachineMismatch,
	PsCreateFailExeName,
	PsCreateSuccess,
	PsCreateMaximumStates
} PS_CREATE_STATE, *PPS_CREATE_STATE;

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef struct _WNF_TYPE_ID
{
	GUID TypeId;
} WNF_TYPE_ID, *PWNF_TYPE_ID;

typedef struct _KEY_VALUE_ENTRY
{
	PUNICODE_STRING ValueName;
	ULONG           DataLength;
	ULONG           DataOffset;
	ULONG           Type;
} KEY_VALUE_ENTRY, *PKEY_VALUE_ENTRY;

typedef enum _KEY_SET_INFORMATION_CLASS
{
	KeyWriteTimeInformation,
	KeyWow64FlagsInformation,
	KeyControlFlagsInformation,
	KeySetVirtualizationInformation,
	KeySetDebugInformation,
	KeySetHandleTagsInformation,
	MaxKeySetInfoClass  // MaxKeySetInfoClass should always be the last enum.
} KEY_SET_INFORMATION_CLASS, *PKEY_SET_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessBreakOnTermination = 29
} PROCESSINFOCLASS, *PPROCESSINFOCLASS;

typedef struct _MEMORY_RANGE_ENTRY
{
	PVOID  VirtualAddress;
	SIZE_T NumberOfBytes;
} MEMORY_RANGE_ENTRY, *PMEMORY_RANGE_ENTRY;

typedef struct _T2_SET_PARAMETERS_V0
{
	ULONG    Version;
	ULONG    Reserved;
	LONGLONG NoWakeTolerance;
} T2_SET_PARAMETERS, *PT2_SET_PARAMETERS;

typedef struct _FILE_PATH
{
	ULONG Version;
	ULONG Length;
	ULONG Type;
	CHAR  FilePath[1];
} FILE_PATH, *PFILE_PATH;

typedef struct _FILE_USER_QUOTA_INFORMATION
{
	ULONG         NextEntryOffset;
	ULONG         SidLength;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER QuotaUsed;
	LARGE_INTEGER QuotaThreshold;
	LARGE_INTEGER QuotaLimit;
	SID           Sid[1];
} FILE_USER_QUOTA_INFORMATION, *PFILE_USER_QUOTA_INFORMATION;

typedef struct _FILE_QUOTA_LIST_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG SidLength;
	SID   Sid[1];
} FILE_QUOTA_LIST_INFORMATION, *PFILE_QUOTA_LIST_INFORMATION;

typedef struct _FILE_NETWORK_OPEN_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	LARGE_INTEGER AllocationSize;
	LARGE_INTEGER EndOfFile;
	ULONG         FileAttributes;
	ULONG         Unknown;
} FILE_NETWORK_OPEN_INFORMATION, *PFILE_NETWORK_OPEN_INFORMATION;

typedef enum _FILTER_BOOT_OPTION_OPERATION
{
	FilterBootOptionOperationOpenSystemStore,
	FilterBootOptionOperationSetElement,
	FilterBootOptionOperationDeleteElement,
	FilterBootOptionOperationMax
} FILTER_BOOT_OPTION_OPERATION, *PFILTER_BOOT_OPTION_OPERATION;

typedef enum _EVENT_TYPE
{
	NotificationEvent = 0,
	SynchronizationEvent = 1,
} EVENT_TYPE, *PEVENT_TYPE;

typedef struct _FILE_FULL_EA_INFORMATION
{
	ULONG  NextEntryOffset;
	UCHAR  Flags;
	UCHAR  EaNameLength;
	USHORT EaValueLength;
	CHAR   EaName[1];
} FILE_FULL_EA_INFORMATION, *PFILE_FULL_EA_INFORMATION;

typedef struct _FILE_GET_EA_INFORMATION
{
	ULONG NextEntryOffset;
	BYTE  EaNameLength;
	CHAR  EaName[1];
} FILE_GET_EA_INFORMATION, *PFILE_GET_EA_INFORMATION;

typedef struct _BOOT_OPTIONS
{
	ULONG Version;
	ULONG Length;
	ULONG Timeout;
	ULONG CurrentBootEntryId;
	ULONG NextBootEntryId;
	WCHAR HeadlessRedirection[1];
} BOOT_OPTIONS, *PBOOT_OPTIONS;

typedef ULONG WNF_CHANGE_STAMP, *PWNF_CHANGE_STAMP;

typedef enum _WNF_DATA_SCOPE
{
	WnfDataScopeSystem = 0,
	WnfDataScopeSession = 1,
	WnfDataScopeUser = 2,
	WnfDataScopeProcess = 3,
	WnfDataScopeMachine = 4
} WNF_DATA_SCOPE, *PWNF_DATA_SCOPE;

typedef enum _WNF_STATE_NAME_LIFETIME
{
	WnfWellKnownStateName = 0,
	WnfPermanentStateName = 1,
	WnfPersistentStateName = 2,
	WnfTemporaryStateName = 3
} WNF_STATE_NAME_LIFETIME, *PWNF_STATE_NAME_LIFETIME;

typedef enum _VIRTUAL_MEMORY_INFORMATION_CLASS
{
	VmPrefetchInformation,
	VmPagePriorityInformation,
	VmCfgCallTargetInformation
} VIRTUAL_MEMORY_INFORMATION_CLASS, *PVIRTUAL_MEMORY_INFORMATION_CLASS;

typedef enum _IO_SESSION_EVENT
{
	IoSessionEventIgnore,
	IoSessionEventCreated,
	IoSessionEventTerminated,
	IoSessionEventConnected,
	IoSessionEventDisconnected,
	IoSessionEventLogon,
	IoSessionEventLogoff,
	IoSessionEventMax
} IO_SESSION_EVENT, *PIO_SESSION_EVENT;

typedef enum _PORT_INFORMATION_CLASS
{
	PortBasicInformation,
#if DEVL
	PortDumpInformation
#endif
} PORT_INFORMATION_CLASS, *PPORT_INFORMATION_CLASS;

typedef enum _PLUGPLAY_CONTROL_CLASS
{
	PlugPlayControlEnumerateDevice,
	PlugPlayControlRegisterNewDevice,
	PlugPlayControlDeregisterDevice,
	PlugPlayControlInitializeDevice,
	PlugPlayControlStartDevice,
	PlugPlayControlUnlockDevice,
	PlugPlayControlQueryAndRemoveDevice,
	PlugPlayControlUserResponse,
	PlugPlayControlGenerateLegacyDevice,
	PlugPlayControlGetInterfaceDeviceList,
	PlugPlayControlProperty,
	PlugPlayControlDeviceClassAssociation,
	PlugPlayControlGetRelatedDevice,
	PlugPlayControlGetInterfaceDeviceAlias,
	PlugPlayControlDeviceStatus,
	PlugPlayControlGetDeviceDepth,
	PlugPlayControlQueryDeviceRelations,
	PlugPlayControlTargetDeviceRelation,
	PlugPlayControlQueryConflictList,
	PlugPlayControlRetrieveDock,
	PlugPlayControlResetDevice,
	PlugPlayControlHaltDevice,
	PlugPlayControlGetBlockedDriverList,
	MaxPlugPlayControl
} PLUGPLAY_CONTROL_CLASS, *PPLUGPLAY_CONTROL_CLASS;

typedef enum _IO_COMPLETION_INFORMATION_CLASS
{
	IoCompletionBasicInformation
} IO_COMPLETION_INFORMATION_CLASS, *PIO_COMPLETION_INFORMATION_CLASS;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef enum _DEBUGOBJECTINFOCLASS
{
	DebugObjectFlags = 1,
	MaxDebugObjectInfoClass
} DEBUGOBJECTINFOCLASS, *PDEBUGOBJECTINFOCLASS;

typedef enum _SEMAPHORE_INFORMATION_CLASS
{
	SemaphoreBasicInformation
} SEMAPHORE_INFORMATION_CLASS, *PSEMAPHORE_INFORMATION_CLASS;

typedef struct _PS_ATTRIBUTE_LIST
{
	SIZE_T       TotalLength;
	PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, *PPS_ATTRIBUTE_LIST;

typedef enum _VDMSERVICECLASS
{
	VdmStartExecution,
	VdmQueueInterrupt,
	VdmDelayInterrupt,
	VdmInitialize,
	VdmFeatures,
	VdmSetInt21Handler,
	VdmQueryDir,
	VdmPrinterDirectIoOpen,
	VdmPrinterDirectIoClose,
	VdmPrinterInitialize,
	VdmSetLdtEntries,
	VdmSetProcessLdtInfo,
	VdmAdlibEmulation,
	VdmPMCliControl,
	VdmQueryVdmProcess
} VDMSERVICECLASS, *PVDMSERVICECLASS;

typedef struct _PS_CREATE_INFO
{
	SIZE_T Size;
	PS_CREATE_STATE State;
	union
	{
		// PsCreateInitialState
		struct {
			union {
				ULONG InitFlags;
				struct {
					UCHAR  WriteOutputOnExit : 1;
					UCHAR  DetectManifest : 1;
					UCHAR  IFEOSkipDebugger : 1;
					UCHAR  IFEODoNotPropagateKeyState : 1;
					UCHAR  SpareBits1 : 4;
					UCHAR  SpareBits2 : 8;
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
					UCHAR  ProtectedProcess : 1;
					UCHAR  AddressSpaceOverride : 1;
					UCHAR  DevOverrideEnabled : 1; // from Image File Execution Options
					UCHAR  ManifestDetected : 1;
					UCHAR  ProtectedProcessLight : 1;
					UCHAR  SpareBits1 : 3;
					UCHAR  SpareBits2 : 8;
					USHORT SpareBits3 : 16;
				};
			};
			HANDLE    FileHandle;
			HANDLE    SectionHandle;
			ULONGLONG UserProcessParametersNative;
			ULONG     UserProcessParametersWow64;
			ULONG     CurrentParameterFlags;
			ULONGLONG PebAddressNative;
			ULONG     PebAddressWow64;
			ULONGLONG ManifestAddress;
			ULONG     ManifestSize;
		} SuccessState;
	};
} PS_CREATE_INFO, *PPS_CREATE_INFO;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

typedef enum _MEMORY_RESERVE_TYPE
{
	MemoryReserveUserApc,
	MemoryReserveIoCompletion,
	MemoryReserveTypeMax
} MEMORY_RESERVE_TYPE, *PMEMORY_RESERVE_TYPE;

typedef enum _ALPC_PORT_INFORMATION_CLASS
{
	AlpcBasicInformation,
	AlpcPortInformation,
	AlpcAssociateCompletionPortInformation,
	AlpcConnectedSIDInformation,
	AlpcServerInformation,
	AlpcMessageZoneInformation,
	AlpcRegisterCompletionListInformation,
	AlpcUnregisterCompletionListInformation,
	AlpcAdjustCompletionListConcurrencyCountInformation,
	AlpcRegisterCallbackInformation,
	AlpcCompletionListRundownInformation
} ALPC_PORT_INFORMATION_CLASS, *PALPC_PORT_INFORMATION_CLASS;

typedef struct _ALPC_CONTEXT_ATTR
{
	PVOID PortContext;
	PVOID MessageContext;
	ULONG SequenceNumber;
	ULONG MessageID;
	ULONG CallbackID;
} ALPC_CONTEXT_ATTR, *PALPC_CONTEXT_ATTR;

typedef struct _ALPC_DATA_VIEW_ATTR
{
	ULONG  Flags;
	HANDLE SectionHandle;
	PVOID  ViewBase;
	SIZE_T ViewSize;
} ALPC_DATA_VIEW_ATTR, *PALPC_DATA_VIEW_ATTR;

typedef struct _ALPC_SECURITY_ATTR
{
	ULONG                        Flags;
	PSECURITY_QUALITY_OF_SERVICE SecurityQos;
	HANDLE                       ContextHandle;
	ULONG                        Reserved1;
	ULONG                        Reserved2;
} ALPC_SECURITY_ATTR, *PALPC_SECURITY_ATTR;

typedef PVOID* PPVOID;

typedef enum _KPROFILE_SOURCE
{
	ProfileTime = 0,
	ProfileAlignmentFixup = 1,
	ProfileTotalIssues = 2,
	ProfilePipelineDry = 3,
	ProfileLoadInstructions = 4,
	ProfilePipelineFrozen = 5,
	ProfileBranchInstructions = 6,
	ProfileTotalNonissues = 7,
	ProfileDcacheMisses = 8,
	ProfileIcacheMisses = 9,
	ProfileCacheMisses = 10,
	ProfileBranchMispredictions = 11,
	ProfileStoreInstructions = 12,
	ProfileFpInstructions = 13,
	ProfileIntegerInstructions = 14,
	Profile2Issue = 15,
	Profile3Issue = 16,
	Profile4Issue = 17,
	ProfileSpecialInstructions = 18,
	ProfileTotalCycles = 19,
	ProfileIcacheIssues = 20,
	ProfileDcacheAccesses = 21,
	ProfileMemoryBarrierCycles = 22,
	ProfileLoadLinkedIssues = 23,
	ProfileMaximum = 24,
} KPROFILE_SOURCE, *PKPROFILE_SOURCE;

typedef enum _ALPC_MESSAGE_INFORMATION_CLASS
{
	AlpcMessageSidInformation,
	AlpcMessageTokenModifiedIdInformation
} ALPC_MESSAGE_INFORMATION_CLASS, *PALPC_MESSAGE_INFORMATION_CLASS;

typedef enum _WORKERFACTORYINFOCLASS
{
	WorkerFactoryTimeout,
	WorkerFactoryRetryTimeout,
	WorkerFactoryIdleTimeout,
	WorkerFactoryBindingCount,
	WorkerFactoryThreadMinimum,
	WorkerFactoryThreadMaximum,
	WorkerFactoryPaused,
	WorkerFactoryBasicInformation,
	WorkerFactoryAdjustThreadGoal,
	WorkerFactoryCallbackType,
	WorkerFactoryStackInformation,
	MaxWorkerFactoryInfoClass
} WORKERFACTORYINFOCLASS, *PWORKERFACTORYINFOCLASS;

typedef enum _MEMORY_PARTITION_INFORMATION_CLASS
{
	SystemMemoryPartitionInformation,
	SystemMemoryPartitionMoveMemory,
	SystemMemoryPartitionAddPagefile,
	SystemMemoryPartitionCombineMemory,
	SystemMemoryPartitionInitialAddMemory,
	SystemMemoryPartitionGetMemoryEvents,
	SystemMemoryPartitionMax
} MEMORY_PARTITION_INFORMATION_CLASS, *PMEMORY_PARTITION_INFORMATION_CLASS;

typedef enum _MUTANT_INFORMATION_CLASS
{
	MutantBasicInformation,
	MutantOwnerInformation
} MUTANT_INFORMATION_CLASS, *PMUTANT_INFORMATION_CLASS;

typedef enum _ATOM_INFORMATION_CLASS
{
	AtomBasicInformation,
	AtomTableInformation
} ATOM_INFORMATION_CLASS, *PATOM_INFORMATION_CLASS;

typedef enum _SHUTDOWN_ACTION {
	ShutdownNoReboot,
	ShutdownReboot,
	ShutdownPowerOff
} SHUTDOWN_ACTION;

typedef VOID(CALLBACK* PTIMER_APC_ROUTINE)(
	IN PVOID TimerContext,
	IN ULONG TimerLowValue,
	IN LONG TimerHighValue);

typedef enum _KEY_VALUE_INFORMATION_CLASS {
	KeyValueBasicInformation = 0,
	KeyValueFullInformation,
	KeyValuePartialInformation,
	KeyValueFullInformationAlign64,
	KeyValuePartialInformationAlign64,
	MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef LANGID* PLANGID;

typedef struct _PLUGPLAY_EVENT_BLOCK
{
	GUID EventGuid;
	PLUGPLAY_EVENT_CATEGORY EventCategory;
	PULONG Result;
	ULONG Flags;
	ULONG TotalSize;
	PVOID DeviceObject;

	union
	{
		struct
		{
			GUID ClassGuid;
			WCHAR SymbolicLinkName[1];
		} DeviceClass;
		struct
		{
			WCHAR DeviceIds[1];
		} TargetDevice;
		struct
		{
			WCHAR DeviceId[1];
		} InstallDevice;
		struct
		{
			PVOID NotificationStructure;
			WCHAR DeviceIds[1];
		} CustomNotification;
		struct
		{
			PVOID Notification;
		} ProfileNotification;
		struct
		{
			ULONG NotificationCode;
			ULONG NotificationData;
		} PowerNotification;
		struct
		{
			PNP_VETO_TYPE VetoType;
			WCHAR DeviceIdVetoNameBuffer[1]; // DeviceId<null>VetoName<null><null>
		} VetoNotification;
		struct
		{
			GUID BlockedDriverGuid;
		} BlockedDriverNotification;
		struct
		{
			WCHAR ParentId[1];
		} InvalidIDNotification;
	} u;
} PLUGPLAY_EVENT_BLOCK, *PPLUGPLAY_EVENT_BLOCK;

typedef VOID(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID            ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG            Reserved);

typedef KNORMAL_ROUTINE* PKNORMAL_ROUTINE;

typedef enum _DIRECTORY_NOTIFY_INFORMATION_CLASS
{
	DirectoryNotifyInformation = 1,
	DirectoryNotifyExtendedInformation = 2,
} DIRECTORY_NOTIFY_INFORMATION_CLASS, *PDIRECTORY_NOTIFY_INFORMATION_CLASS;

typedef enum _EVENT_INFORMATION_CLASS
{
	EventBasicInformation
} EVENT_INFORMATION_CLASS, *PEVENT_INFORMATION_CLASS;

typedef struct _ALPC_MESSAGE_ATTRIBUTES
{
	unsigned long AllocatedAttributes;
	unsigned long ValidAttributes;
} ALPC_MESSAGE_ATTRIBUTES, *PALPC_MESSAGE_ATTRIBUTES;

typedef struct _ALPC_PORT_ATTRIBUTES
{
	ULONG                       Flags;
	SECURITY_QUALITY_OF_SERVICE SecurityQos;
	SIZE_T                      MaxMessageLength;
	SIZE_T                      MemoryBandwidth;
	SIZE_T                      MaxPoolUsage;
	SIZE_T                      MaxSectionSize;
	SIZE_T                      MaxViewSize;
	SIZE_T                      MaxTotalSectionSize;
	ULONG                       DupObjectTypes;
#ifdef _WIN64
	ULONG                       Reserved;
#endif
} ALPC_PORT_ATTRIBUTES, *PALPC_PORT_ATTRIBUTES;

typedef enum _IO_SESSION_STATE
{
	IoSessionStateCreated = 1,
	IoSessionStateInitialized = 2,
	IoSessionStateConnected = 3,
	IoSessionStateDisconnected = 4,
	IoSessionStateDisconnectedLoggedOn = 5,
	IoSessionStateLoggedOn = 6,
	IoSessionStateLoggedOff = 7,
	IoSessionStateTerminated = 8,
	IoSessionStateMax = 9,
} IO_SESSION_STATE, *PIO_SESSION_STATE;

typedef const WNF_STATE_NAME *PCWNF_STATE_NAME;

typedef const WNF_TYPE_ID *PCWNF_TYPE_ID;

typedef struct _WNF_DELIVERY_DESCRIPTOR
{
	unsigned __int64 SubscriptionId;
	WNF_STATE_NAME   StateName;
	unsigned long    ChangeStamp;
	unsigned long    StateDataSize;
	unsigned long    EventMask;
	WNF_TYPE_ID      TypeId;
	unsigned long    StateDataOffset;
} WNF_DELIVERY_DESCRIPTOR, *PWNF_DELIVERY_DESCRIPTOR;

typedef enum _DEBUG_CONTROL_CODE
{
	SysDbgQueryModuleInformation = 0,
	SysDbgQueryTraceInformation = 1,
	SysDbgSetTracePoint = 2,
	SysDbgSetSpecialCall = 3,
	SysDbgClearSpecialCalls = 4,
	SysDbgQuerySpecialCalls = 5,
	SysDbgBreakPoint = 6,
	SysDbgQueryVersion = 7,
	SysDbgReadVirtual = 8,
	SysDbgWriteVirtual = 9,
	SysDbgReadPhysical = 10,
	SysDbgWritePhysical = 11,
	SysDbgReadControlSpace = 12,
	SysDbgWriteControlSpace = 13,
	SysDbgReadIoSpace = 14,
	SysDbgWriteIoSpace = 15,
	SysDbgReadMsr = 16,
	SysDbgWriteMsr = 17,
	SysDbgReadBusData = 18,
	SysDbgWriteBusData = 19,
	SysDbgCheckLowMemory = 20,
	SysDbgEnableKernelDebugger = 21,
	SysDbgDisableKernelDebugger = 22,
	SysDbgGetAutoKdEnable = 23,
	SysDbgSetAutoKdEnable = 24,
	SysDbgGetPrintBufferSize = 25,
	SysDbgSetPrintBufferSize = 26,
	SysDbgGetKdUmExceptionEnable = 27,
	SysDbgSetKdUmExceptionEnable = 28,
	SysDbgGetTriageDump = 29,
	SysDbgGetKdBlockEnable = 30,
	SysDbgSetKdBlockEnable = 31
} DEBUG_CONTROL_CODE, *PDEBUG_CONTROL_CODE;

typedef struct _PORT_MESSAGE
{
	union
	{
		union
		{
			struct
			{
				short DataLength;
				short TotalLength;
			} s1;
			unsigned long Length;
		};
	} u1;
	union
	{
		union
		{
			struct
			{
				short Type;
				short DataInfoOffset;
			} s2;
			unsigned long ZeroInit;
		};
	} u2;
	union
	{
		CLIENT_ID ClientId;
		double    DoNotUseThisField;
	};
	unsigned long MessageId;
	union
	{
		unsigned __int64 ClientViewSize;
		struct
		{
			unsigned long CallbackId;
			long          __PADDING__[1];
		};
	};
} PORT_MESSAGE, *PPORT_MESSAGE;

typedef struct FILE_BASIC_INFORMATION
{
	LARGE_INTEGER CreationTime;
	LARGE_INTEGER LastAccessTime;
	LARGE_INTEGER LastWriteTime;
	LARGE_INTEGER ChangeTime;
	ULONG         FileAttributes;
} FILE_BASIC_INFORMATION, *PFILE_BASIC_INFORMATION;

typedef struct _PORT_SECTION_READ
{
	ULONG Length;
	ULONG ViewSize;
	ULONG ViewBase;
} PORT_SECTION_READ, *PPORT_SECTION_READ;

typedef struct _PORT_SECTION_WRITE
{
	ULONG  Length;
	HANDLE SectionHandle;
	ULONG  SectionOffset;
	ULONG  ViewSize;
	PVOID  ViewBase;
	PVOID  TargetViewBase;
} PORT_SECTION_WRITE, *PPORT_SECTION_WRITE;

typedef enum _TIMER_TYPE
{
	NotificationTimer,
	SynchronizationTimer
} TIMER_TYPE, *PTIMER_TYPE;

typedef struct _BOOT_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG BootFilePathOffset;
	ULONG OsOptionsLength;
	UCHAR OsOptions[ANYSIZE_ARRAY];
} BOOT_ENTRY, *PBOOT_ENTRY;

typedef struct _EFI_DRIVER_ENTRY
{
	ULONG Version;
	ULONG Length;
	ULONG Id;
	ULONG Attributes;
	ULONG FriendlyNameOffset;
	ULONG DriverFilePathOffset;
} EFI_DRIVER_ENTRY, *PEFI_DRIVER_ENTRY;

typedef USHORT RTL_ATOM, *PRTL_ATOM;

typedef enum _TIMER_SET_INFORMATION_CLASS
{
	TimerSetCoalescableTimer,
	MaxTimerInfoClass
} TIMER_SET_INFORMATION_CLASS, *PTIMER_SET_INFORMATION_CLASS;

typedef enum _FSINFOCLASS
{
	FileFsVolumeInformation = 1,
	FileFsLabelInformation = 2,
	FileFsSizeInformation = 3,
	FileFsDeviceInformation = 4,
	FileFsAttributeInformation = 5,
	FileFsControlInformation = 6,
	FileFsFullSizeInformation = 7,
	FileFsObjectIdInformation = 8,
	FileFsDriverPathInformation = 9,
	FileFsVolumeFlagsInformation = 10,
	FileFsSectorSizeInformation = 11,
	FileFsDataCopyInformation = 12,
	FileFsMetadataSizeInformation = 13,
	FileFsFullSizeInformationEx = 14,
	FileFsMaximumInformation = 15,
} FSINFOCLASS, *PFSINFOCLASS;

typedef enum _WAIT_TYPE
{
	WaitAll = 0,
	WaitAny = 1
} WAIT_TYPE, *PWAIT_TYPE;

typedef struct _USER_STACK
{
	PVOID FixedStackBase;
	PVOID FixedStackLimit;
	PVOID ExpandableStackBase;
	PVOID ExpandableStackLimit;
	PVOID ExpandableStackBottom;
} USER_STACK, *PUSER_STACK;

typedef enum _SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation,
} SECTION_INFORMATION_CLASS, *PSECTION_INFORMATION_CLASS;

typedef enum _APPHELPCACHESERVICECLASS
{
	ApphelpCacheServiceLookup = 0,
	ApphelpCacheServiceRemove = 1,
	ApphelpCacheServiceUpdate = 2,
	ApphelpCacheServiceFlush = 3,
	ApphelpCacheServiceDump = 4,
	ApphelpDBGReadRegistry = 0x100,
	ApphelpDBGWriteRegistry = 0x101,
} APPHELPCACHESERVICECLASS, *PAPPHELPCACHESERVICECLASS;

typedef struct _TOKEN_SECURITY_ATTRIBUTES_INFORMATION
{
	USHORT Version;
	USHORT Reserved;
	ULONG  AttributeCount;
	union
	{
		PTOKEN_SECURITY_ATTRIBUTE_V1 pAttributeV1;
	} Attribute;
} TOKEN_SECURITY_ATTRIBUTES_INFORMATION, *PTOKEN_SECURITY_ATTRIBUTES_INFORMATION;

typedef struct _FILE_IO_COMPLETION_INFORMATION
{
	PVOID           KeyContext;
	PVOID           ApcContext;
	IO_STATUS_BLOCK IoStatusBlock;
} FILE_IO_COMPLETION_INFORMATION, *PFILE_IO_COMPLETION_INFORMATION;

typedef PVOID PT2_CANCEL_PARAMETERS;

typedef enum _THREADINFOCLASS
{
	ThreadBasicInformation,
	ThreadTimes,
	ThreadPriority,
	ThreadBasePriority,
	ThreadAffinityMask,
	ThreadImpersonationToken,
	ThreadDescriptorTableEntry,
	ThreadEnableAlignmentFaultFixup,
	ThreadEventPair_Reusable,
	ThreadQuerySetWin32StartAddress,
	ThreadZeroTlsCell,
	ThreadPerformanceCount,
	ThreadAmILastThread,
	ThreadIdealProcessor,
	ThreadPriorityBoost,
	ThreadSetTlsArrayAddress,
	ThreadIsIoPending,
	ThreadHideFromDebugger,
	ThreadBreakOnTermination,
	MaxThreadInfoClass
} THREADINFOCLASS, *PTHREADINFOCLASS;

typedef enum _OBJECT_INFORMATION_CLASS
{
	ObjectBasicInformation,
	ObjectNameInformation,
	ObjectTypeInformation,
	ObjectAllTypesInformation,
	ObjectHandleInformation
} OBJECT_INFORMATION_CLASS, *POBJECT_INFORMATION_CLASS;

typedef enum _FILE_INFORMATION_CLASS
{
	FileDirectoryInformation = 1,
	FileFullDirectoryInformation = 2,
	FileBothDirectoryInformation = 3,
	FileBasicInformation = 4,
	FileStandardInformation = 5,
	FileInternalInformation = 6,
	FileEaInformation = 7,
	FileAccessInformation = 8,
	FileNameInformation = 9,
	FileRenameInformation = 10,
	FileLinkInformation = 11,
	FileNamesInformation = 12,
	FileDispositionInformation = 13,
	FilePositionInformation = 14,
	FileFullEaInformation = 15,
	FileModeInformation = 16,
	FileAlignmentInformation = 17,
	FileAllInformation = 18,
	FileAllocationInformation = 19,
	FileEndOfFileInformation = 20,
	FileAlternateNameInformation = 21,
	FileStreamInformation = 22,
	FilePipeInformation = 23,
	FilePipeLocalInformation = 24,
	FilePipeRemoteInformation = 25,
	FileMailslotQueryInformation = 26,
	FileMailslotSetInformation = 27,
	FileCompressionInformation = 28,
	FileObjectIdInformation = 29,
	FileCompletionInformation = 30,
	FileMoveClusterInformation = 31,
	FileQuotaInformation = 32,
	FileReparsePointInformation = 33,
	FileNetworkOpenInformation = 34,
	FileAttributeTagInformation = 35,
	FileTrackingInformation = 36,
	FileIdBothDirectoryInformation = 37,
	FileIdFullDirectoryInformation = 38,
	FileValidDataLengthInformation = 39,
	FileShortNameInformation = 40,
	FileIoCompletionNotificationInformation = 41,
	FileIoStatusBlockRangeInformation = 42,
	FileIoPriorityHintInformation = 43,
	FileSfioReserveInformation = 44,
	FileSfioVolumeInformation = 45,
	FileHardLinkInformation = 46,
	FileProcessIdsUsingFileInformation = 47,
	FileNormalizedNameInformation = 48,
	FileNetworkPhysicalNameInformation = 49,
	FileIdGlobalTxDirectoryInformation = 50,
	FileIsRemoteDeviceInformation = 51,
	FileUnusedInformation = 52,
	FileNumaNodeInformation = 53,
	FileStandardLinkInformation = 54,
	FileRemoteProtocolInformation = 55,
	FileRenameInformationBypassAccessCheck = 56,
	FileLinkInformationBypassAccessCheck = 57,
	FileVolumeNameInformation = 58,
	FileIdInformation = 59,
	FileIdExtdDirectoryInformation = 60,
	FileReplaceCompletionInformation = 61,
	FileHardLinkFullIdInformation = 62,
	FileIdExtdBothDirectoryInformation = 63,
	FileDispositionInformationEx = 64,
	FileRenameInformationEx = 65,
	FileRenameInformationExBypassAccessCheck = 66,
	FileMaximumInformation = 67,
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;

typedef enum _KEY_INFORMATION_CLASS
{
	KeyBasicInformation = 0,
	KeyNodeInformation = 1,
	KeyFullInformation = 2,
	KeyNameInformation = 3,
	KeyCachedInformation = 4,
	KeyFlagsInformation = 5,
	KeyVirtualizationInformation = 6,
	KeyHandleTagsInformation = 7,
	MaxKeyInfoClass = 8
} KEY_INFORMATION_CLASS, *PKEY_INFORMATION_CLASS;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef enum _TIMER_INFORMATION_CLASS
{
	TimerBasicInformation
} TIMER_INFORMATION_CLASS, *PTIMER_INFORMATION_CLASS;

EXTERN_C NTSTATUS NtCompareObjects(
	IN HANDLE FirstObjectHandle,
	IN HANDLE SecondObjectHandle);

EXTERN_C NTSTATUS NtAllocateUuids(
	OUT PLARGE_INTEGER Time,
	OUT PULONG Range,
	OUT PULONG Sequence,
	OUT PUCHAR Seed);

EXTERN_C NTSTATUS NtFlushBuffersFileEx(
	IN HANDLE FileHandle,
	IN ULONG Flags,
	IN PVOID Parameters,
	IN ULONG ParametersSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtQueryInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	OUT PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtRemoveIoCompletion(
	IN HANDLE IoCompletionHandle,
	OUT PULONG KeyContext,
	OUT PULONG ApcContext,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtCreateLowBoxToken(
	OUT PHANDLE TokenHandle,
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PSID PackageSid,
	IN ULONG CapabilityCount,
	IN PSID_AND_ATTRIBUTES Capabilities OPTIONAL,
	IN ULONG HandleCount,
	IN HANDLE Handles OPTIONAL);

EXTERN_C NTSTATUS NtQueryAuxiliaryCounterFrequency(
	OUT PULONGLONG lpAuxiliaryCounterFrequency);

EXTERN_C NTSTATUS NtContinue(
	IN PCONTEXT ContextRecord,
	IN BOOLEAN TestAlert);

EXTERN_C NTSTATUS NtUnloadKey(
	IN POBJECT_ATTRIBUTES DestinationKeyName);

EXTERN_C NTSTATUS NtCompressKey(
	IN HANDLE Key);

EXTERN_C NTSTATUS NtWaitForMultipleObjects32(
	IN ULONG ObjectCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtPropagationComplete(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN ULONG BufferLength,
	IN PVOID Buffer);

EXTERN_C NTSTATUS NtQueryInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	OUT PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryIntervalProfile(
	IN KPROFILE_SOURCE ProfileSource,
	OUT PULONG Interval);

EXTERN_C NTSTATUS NtAccessCheckByType(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ULONG DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtOpenEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtQueryTimerResolution(
	OUT PULONG MaximumTime,
	OUT PULONG MinimumTime,
	OUT PULONG CurrentTime);

EXTERN_C NTSTATUS NtFreezeRegistry(
	IN ULONG TimeOutInSeconds);

EXTERN_C NTSTATUS NtDuplicateToken(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtQueryInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	OUT PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtUnloadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtTerminateJobObject(
	IN HANDLE JobHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtRequestWaitReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage,
	OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtThawTransactions();

EXTERN_C NTSTATUS NtListenPort(
	IN HANDLE PortHandle,
	OUT PPORT_MESSAGE ConnectionRequest);

EXTERN_C NTSTATUS NtOpenKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtModifyBootEntry(
	IN PBOOT_ENTRY BootEntry);

EXTERN_C NTSTATUS NtCreateSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PUNICODE_STRING LinkTarget);

EXTERN_C NTSTATUS NtEnumerateKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtGetCurrentProcessorNumber();

EXTERN_C NTSTATUS NtWaitForKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID Key,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationTransactionManager(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtSetThreadExecutionState(
	IN EXECUTION_STATE ExecutionState,
	OUT PEXECUTION_STATE PreviousExecutionState);

EXTERN_C NTSTATUS NtOpenMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtVdmControl(
	IN VDMSERVICECLASS Service,
	IN OUT PVOID ServiceData);

EXTERN_C NTSTATUS NtPrePrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtAreMappedFilesTheSame(
	IN PVOID File1MappedAsAnImage,
	IN PVOID File2MappedAsFile);

EXTERN_C NTSTATUS NtSetHighWaitLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtSetEventBoostPriority(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtQueryBootOptions(
	OUT PBOOT_OPTIONS BootOptions OPTIONAL,
	IN OUT PULONG BootOptionsLength);

EXTERN_C NTSTATUS NtAlpcOpenSenderProcess(
	OUT PHANDLE ProcessHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtSetDefaultHardErrorPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtLoadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtTerminateEnclave(
	IN PVOID BaseAddress,
	IN BOOLEAN WaitForThread);

EXTERN_C NTSTATUS NtOpenEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN LPGUID EnlistmentGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtWriteRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Request,
	IN ULONG DataIndex,
	IN PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ResultLength OPTIONAL);

EXTERN_C NTSTATUS NtGetNextThread(
	IN HANDLE ProcessHandle,
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewThreadHandle);

EXTERN_C NTSTATUS NtCancelTimer(
	IN HANDLE TimerHandle,
	OUT PBOOLEAN CurrentState OPTIONAL);

EXTERN_C NTSTATUS NtCreateCrossVmEvent();

EXTERN_C NTSTATUS NtModifyDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry);

EXTERN_C NTSTATUS NtRollbackComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtQueryValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtSetInformationWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN WORKERFACTORYINFOCLASS WorkerFactoryInformationClass,
	IN PVOID WorkerFactoryInformation,
	IN ULONG WorkerFactoryInformationLength);

EXTERN_C NTSTATUS NtFreezeTransactions(
	IN PLARGE_INTEGER FreezeTimeout,
	IN PLARGE_INTEGER ThawTimeout);

EXTERN_C NTSTATUS NtDeleteObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtQueryPortInformationProcess();

EXTERN_C NTSTATUS NtDeleteFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCreateNamedPipeFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN BOOLEAN NamedPipeType,
	IN BOOLEAN ReadMode,
	IN BOOLEAN CompletionMode,
	IN ULONG MaximumInstances,
	IN ULONG InboundQuota,
	IN ULONG OutboundQuota,
	IN PLARGE_INTEGER DefaultTimeout OPTIONAL);

EXTERN_C NTSTATUS NtAcceptConnectPort(
	OUT PHANDLE ServerPortHandle,
	IN ULONG AlternativeReceivePortHandle OPTIONAL,
	IN PPORT_MESSAGE ConnectionReply,
	IN BOOLEAN AcceptConnection,
	IN OUT PPORT_SECTION_WRITE ServerSharedMemory OPTIONAL,
	OUT PPORT_SECTION_READ ClientSharedMemory OPTIONAL);

EXTERN_C NTSTATUS NtDeleteValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName);

EXTERN_C NTSTATUS NtOpenIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtReplyPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtSetDefaultUILanguage(
	IN LANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtWaitForMultipleObjects(
	IN ULONG Count,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitType,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtQueryMultipleValueKey(
	IN HANDLE KeyHandle,
	IN OUT PKEY_VALUE_ENTRY ValueEntries,
	IN ULONG EntryCount,
	OUT PVOID ValueBuffer,
	IN PULONG BufferLength,
	OUT PULONG RequiredBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtCommitRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtCreateWorkerFactory(
	OUT PHANDLE WorkerFactoryHandleReturn,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE CompletionPortHandle,
	IN HANDLE WorkerProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID StartParameter OPTIONAL,
	IN ULONG MaxThreadCount OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL);

EXTERN_C NTSTATUS NtCancelDeviceWakeupRequest(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtPrivilegeObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtCreateTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LPGUID Uow OPTIONAL,
	IN HANDLE TmHandle OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG IsolationLevel OPTIONAL,
	IN ULONG IsolationFlags OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtCreateSectionEx(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL,
	IN PMEM_EXTENDED_PARAMETER ExtendedParameters,
	IN ULONG ExtendedParametersCount);

EXTERN_C NTSTATUS NtPowerInformation(
	IN POWER_INFORMATION_LEVEL InformationLevel,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtWaitForWnfNotifications();

EXTERN_C NTSTATUS NtOpenResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID ResourceManagerGuid OPTIONAL,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtEnumerateSystemEnvironmentValuesEx(
	IN ULONG InformationClass,
	OUT PVOID Buffer,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtDeleteKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtSerializeBoot();

EXTERN_C NTSTATUS NtMapUserPhysicalPagesScatter(
	IN PVOID VirtualAddresses,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtSetBootOptions(
	IN PBOOT_OPTIONS BootOptions,
	IN ULONG FieldsToChange);

EXTERN_C NTSTATUS NtOpenKeyEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtInitializeEnclave(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtQueryPerformanceCounter(
	OUT PLARGE_INTEGER PerformanceCounter,
	OUT PLARGE_INTEGER PerformanceFrequency OPTIONAL);

EXTERN_C NTSTATUS NtSetDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level,
	IN BOOLEAN State);

EXTERN_C NTSTATUS NtRollbackEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtShutdownWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	IN OUT PLONG PendingWorkerCount);

EXTERN_C NTSTATUS NtWaitForAlertByThreadId(
	IN HANDLE Handle,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtCreateFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PLARGE_INTEGER AllocationSize OPTIONAL,
	IN ULONG FileAttributes,
	IN ULONG ShareAccess,
	IN ULONG CreateDisposition,
	IN ULONG CreateOptions,
	IN PVOID EaBuffer OPTIONAL,
	IN ULONG EaLength);

EXTERN_C NTSTATUS NtSetInformationJobObject(
	IN HANDLE JobHandle,
	IN JOBOBJECTINFOCLASS JobObjectInformationClass,
	IN PVOID JobObjectInformation,
	IN ULONG JobObjectInformationLength);

EXTERN_C NTSTATUS NtThawRegistry();

EXTERN_C NTSTATUS NtSetSystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID SystemInformation,
	IN ULONG SystemInformationLength);

EXTERN_C NTSTATUS NtInitiatePowerAction(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE LightestSystemState,
	IN ULONG Flags,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtCommitComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtResetWriteWatch(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN ULONG RegionSize);

EXTERN_C NTSTATUS NtSetInformationKey(
	IN HANDLE KeyHandle,
	IN KEY_SET_INFORMATION_CLASS KeySetInformationClass,
	IN PVOID KeySetInformation,
	IN ULONG KeySetInformationLength);

EXTERN_C NTSTATUS NtAllocateReserveObject(
	OUT PHANDLE MemoryReserveHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN MEMORY_RESERVE_TYPE Type);

EXTERN_C NTSTATUS NtCreateProcessEx(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL,
	IN ULONG JobMemberLevel);

EXTERN_C NTSTATUS NtRemoveIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	OUT PFILE_IO_COMPLETION_INFORMATION IoCompletionInformation,
	IN ULONG Count,
	OUT PULONG NumEntriesRemoved,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	IN BOOLEAN Alertable);

EXTERN_C NTSTATUS NtRenameTransactionManager(
	IN PUNICODE_STRING LogFileName,
	IN LPGUID ExistingTransactionManagerGuid);

EXTERN_C NTSTATUS NtQuerySection(
	IN HANDLE SectionHandle,
	IN SECTION_INFORMATION_CLASS SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAllocateUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	OUT PULONG UserPfnArray);

EXTERN_C NTSTATUS NtOpenObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN ACCESS_MASK GrantedAccess,
	IN PPRIVILEGE_SET Privileges OPTIONAL,
	IN BOOLEAN ObjectCreation,
	IN BOOLEAN AccessGranted,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtAlertResumeThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtSetLowEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtRollforwardTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtQuerySemaphore(
	IN HANDLE SemaphoreHandle,
	IN SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
	OUT PVOID SemaphoreInformation,
	IN ULONG SemaphoreInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtRaiseHardError(
	IN NTSTATUS ErrorStatus,
	IN ULONG NumberOfParameters,
	IN ULONG UnicodeStringParameterMask,
	IN PULONG_PTR Parameters,
	IN ULONG ValidResponseOptions,
	OUT PULONG Response);

EXTERN_C NTSTATUS NtTraceControl(
	IN ULONG FunctionCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtWriteVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN ULONG NumberOfBytesToWrite,
	OUT PULONG NumberOfBytesWritten OPTIONAL);

EXTERN_C NTSTATUS NtCloseObjectAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN BOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtAddBootEntry(
	IN PBOOT_ENTRY BootEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtCancelIoFileEx(
	IN HANDLE FileHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtDebugContinue(
	IN HANDLE DebugObjectHandle,
	IN PCLIENT_ID ClientId,
	IN NTSTATUS ContinueStatus);

EXTERN_C NTSTATUS NtNotifyChangeSession(
	IN HANDLE SessionHandle,
	IN ULONG ChangeSequenceNumber,
	IN PLARGE_INTEGER ChangeTimeStamp,
	IN IO_SESSION_EVENT Event,
	IN IO_SESSION_STATE NewState,
	IN IO_SESSION_STATE PreviousState,
	IN PVOID Payload OPTIONAL,
	IN ULONG PayloadSize);

EXTERN_C NTSTATUS NtOpenRegistryTransaction(
	OUT PHANDLE RegistryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtRollbackTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtSetTimer2(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PLARGE_INTEGER Period OPTIONAL,
	IN PT2_SET_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtQueryInformationByName(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS NtCreateJobSet(
	IN ULONG NumJob,
	IN PJOB_SET_ARRAY UserJobSet,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtOpenJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtFlushInstallUILanguage(
	IN LANGID InstallUILanguage,
	IN ULONG SetComittedFlag);

EXTERN_C NTSTATUS NtRevertContainerImpersonation();

EXTERN_C NTSTATUS NtFlushBuffersFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtAssociateWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN HANDLE IoCompletionHandle,
	IN HANDLE TargetObjectHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation,
	OUT PBOOLEAN AlreadySignaled OPTIONAL);

EXTERN_C NTSTATUS NtLockProductActivationKeys(
	IN OUT PULONG pPrivateVer OPTIONAL,
	OUT PULONG pSafeMode OPTIONAL);

EXTERN_C NTSTATUS NtAlpcRevokeSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtAlpcQueryInformationMessage(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ALPC_MESSAGE_INFORMATION_CLASS MessageInformationClass,
	OUT PVOID MessageInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtReleaseKeyedEvent(
	IN HANDLE KeyedEventHandle,
	IN PVOID KeyValue,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtInitializeRegistry(
	IN USHORT BootCondition);

EXTERN_C NTSTATUS NtMapCMFModule(
	IN ULONG What,
	IN ULONG Index,
	OUT PULONG CacheIndexOut OPTIONAL,
	OUT PULONG CacheFlagsOut OPTIONAL,
	OUT PULONG ViewSizeOut OPTIONAL,
	OUT PVOID BaseAddress OPTIONAL);

EXTERN_C NTSTATUS NtCreateRegistryTransaction(
	OUT PHANDLE Handle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN DWORD Flags);

EXTERN_C NTSTATUS NtMapViewOfSection(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN SIZE_T CommitSize,
	IN OUT PLARGE_INTEGER SectionOffset OPTIONAL,
	IN OUT PSIZE_T ViewSize,
	IN SECTION_INHERIT InheritDisposition,
	IN ULONG AllocationType,
	IN ULONG Win32Protect);

EXTERN_C NTSTATUS NtCreateEnlistment(
	OUT PHANDLE EnlistmentHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE ResourceManagerHandle,
	IN HANDLE TransactionHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN NOTIFICATION_MASK NotificationMask,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtEnumerateTransactionObject(
	IN HANDLE RootObjectHandle OPTIONAL,
	IN KTMOBJECT_TYPE QueryType,
	IN OUT PKTMOBJECT_CURSOR ObjectCursor,
	IN ULONG ObjectCursorLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtQueryAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_BASIC_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtSetHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtAlpcSetInformation(
	IN HANDLE PortHandle,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN PVOID PortInformation OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtFlushWriteBuffer();

EXTERN_C NTSTATUS NtCreateEnclave(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG_PTR ZeroBits,
	IN SIZE_T Size,
	IN SIZE_T InitialCommitment,
	IN ULONG EnclaveType,
	IN PVOID EnclaveInformation,
	IN ULONG EnclaveInformationLength,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtFreeUserPhysicalPages(
	IN HANDLE ProcessHandle,
	IN OUT PULONG NumberOfPages,
	IN PULONG UserPfnArray);

EXTERN_C NTSTATUS NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtCreateTimer2(
	OUT PHANDLE TimerHandle,
	IN PVOID Reserved1 OPTIONAL,
	IN PVOID Reserved2 OPTIONAL,
	IN ULONG Attributes,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PLARGE_INTEGER MaximumSize OPTIONAL,
	IN ULONG SectionPageProtection,
	IN ULONG AllocationAttributes,
	IN HANDLE FileHandle OPTIONAL);

EXTERN_C NTSTATUS NtOpenKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtQueryQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_QUOTA_LIST_INFORMATION SidList OPTIONAL,
	IN ULONG SidListLength,
	IN PSID StartSid OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtCreateKeyedEvent(
	OUT PHANDLE KeyedEventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtDeviceIoControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG IoControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtUnmapViewOfSectionEx(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtAcquireCMFViewOwnership(
	OUT BOOLEAN TimeStamp,
	OUT BOOLEAN TokenTaken,
	IN BOOLEAN ReplaceExisting);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	OUT PVOID Value OPTIONAL,
	IN OUT PULONG ValueLength,
	OUT PULONG Attributes OPTIONAL);

EXTERN_C NTSTATUS NtYieldExecution();

EXTERN_C NTSTATUS NtCreateDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAddAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtIsSystemResumeAutomatic();

EXTERN_C NTSTATUS NtOpenPartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtRecoverTransactionManager(
	IN HANDLE TransactionManagerHandle);

EXTERN_C NTSTATUS NtQueryDriverEntryOrder(
	IN PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtCreateTokenEx(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION UserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION DeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroups OPTIONAL,
	IN PTOKEN_MANDATORY_POLICY TokenMandatoryPolicy OPTIONAL,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCreatePagingFile(
	IN PUNICODE_STRING PageFileName,
	IN PULARGE_INTEGER MinimumSize,
	IN PULARGE_INTEGER MaximumSize,
	IN ULONG Priority);

EXTERN_C NTSTATUS NtPrepareComplete(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtStartTm();

EXTERN_C NTSTATUS NtCreateProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ParentProcess,
	IN BOOLEAN InheritObjectTable,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL);

EXTERN_C NTSTATUS NtPullTransaction();

EXTERN_C NTSTATUS NtQueryDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL);

EXTERN_C NTSTATUS NtOpenTransaction(
	OUT PHANDLE TransactionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN LPGUID Uow,
	IN HANDLE TmHandle OPTIONAL);

EXTERN_C NTSTATUS NtRecoverEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PVOID EnlistmentKey OPTIONAL);

EXTERN_C NTSTATUS NtCreateEvent(
	OUT PHANDLE EventHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN EVENT_TYPE EventType,
	IN BOOLEAN InitialState);

EXTERN_C NTSTATUS NtRegisterThreadTerminatePort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtQueryInstallUILanguage(
	OUT PLANGID InstallUILanguageId);

EXTERN_C NTSTATUS NtOpenKeyTransactedEx(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG OpenOptions,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtQuerySecurityPolicy(
	IN ULONG_PTR UnknownParameter1,
	IN ULONG_PTR UnknownParameter2,
	IN ULONG_PTR UnknownParameter3,
	IN ULONG_PTR UnknownParameter4,
	IN ULONG_PTR UnknownParameter5,
	IN ULONG_PTR UnknownParameter6);

EXTERN_C NTSTATUS NtQueryEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_FULL_EA_INFORMATION Buffer,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN PFILE_GET_EA_INFORMATION EaList OPTIONAL,
	IN ULONG EaListLength,
	IN PULONG EaIndex OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtImpersonateThread(
	IN HANDLE ServerThreadHandle,
	IN HANDLE ClientThreadHandle,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos);

EXTERN_C NTSTATUS NtGetNotificationResourceManager(
	IN HANDLE ResourceManagerHandle,
	OUT PTRANSACTION_NOTIFICATION TransactionNotification,
	IN ULONG NotificationLength,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL,
	IN ULONG Asynchronous,
	IN ULONG AsynchronousContext OPTIONAL);

EXTERN_C NTSTATUS NtCreateMailslotFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CreateOptions,
	IN ULONG MailslotQuota,
	IN ULONG MaximumMessageSize,
	IN PLARGE_INTEGER ReadTimeout);

EXTERN_C NTSTATUS NtSetLdtEntries(
	IN ULONG Selector0,
	IN ULONG Entry0Low,
	IN ULONG Entry0Hi,
	IN ULONG Selector1,
	IN ULONG Entry1Low,
	IN ULONG Entry1Hi);

EXTERN_C NTSTATUS NtFlushKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtDrawText(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtGetContextThread(
	IN HANDLE ThreadHandle,
	IN OUT PCONTEXT ThreadContext);

EXTERN_C NTSTATUS NtCreateIoCompletion(
	OUT PHANDLE IoCompletionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG Count OPTIONAL);

EXTERN_C NTSTATUS NtOpenTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtLoadKey(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile);

EXTERN_C NTSTATUS NtMakeTemporaryObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtSetValueKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING ValueName,
	IN ULONG TitleIndex OPTIONAL,
	IN ULONG Type,
	IN PVOID SystemData,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtFlushProcessWriteBuffers();

EXTERN_C NTSTATUS NtPrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSetCachedSigningLevel2(
	IN ULONG Flags,
	IN ULONG InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL,
	IN PVOID LevelInformation OPTIONAL);

EXTERN_C NTSTATUS NtConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PULONG BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtUnlockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG NumberOfBytesToUnlock,
	IN ULONG LockType);

EXTERN_C NTSTATUS NtQueryObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtLockVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PULONG RegionSize,
	IN ULONG MapType);

EXTERN_C NTSTATUS NtAlpcQueryInformation(
	IN HANDLE PortHandle OPTIONAL,
	IN ALPC_PORT_INFORMATION_CLASS PortInformationClass,
	IN OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtQueryOpenSubKeysEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN ULONG BufferLength,
	OUT PVOID Buffer,
	OUT PULONG RequiredSize);

EXTERN_C NTSTATUS NtDeleteBootEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtAlpcDeleteSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PVOID ViewBase);

EXTERN_C NTSTATUS NtManageHotPatch(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtGetCachedSigningLevel(
	IN HANDLE File,
	OUT PULONG Flags,
	OUT PSE_SIGNING_LEVEL SigningLevel,
	OUT PUCHAR Thumbprint OPTIONAL,
	IN OUT PULONG ThumbprintSize OPTIONAL,
	OUT PULONG ThumbprintAlgorithm OPTIONAL);

EXTERN_C NTSTATUS NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2,
	IN ULONG UnknownParameter3,
	IN ULONG UnknownParameter4);

EXTERN_C NTSTATUS NtSetWnfProcessNotificationEvent(
	IN HANDLE NotificationEvent);

EXTERN_C NTSTATUS NtOpenProcessTokenEx(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtCancelWaitCompletionPacket(
	IN HANDLE WaitCompletionPacketHandle,
	IN BOOLEAN RemoveSignaledPacket);

EXTERN_C NTSTATUS NtPrePrepareEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSuspendProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSuspendThread(
	IN HANDLE ThreadHandle,
	OUT PULONG PreviousSuspendCount);

EXTERN_C NTSTATUS NtAlpcConnectPortEx(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ConnectionPortObjectAttributes,
	IN POBJECT_ATTRIBUTES ClientPortObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN ULONG Flags,
	IN PSECURITY_DESCRIPTOR ServerSecurityRequirements OPTIONAL,
	IN OUT PPORT_MESSAGE ConnectionMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES OutMessageAttributes OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES InMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtStopProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtPlugPlayControl(
	IN PLUGPLAY_CONTROL_CLASS PnPControlClass,
	IN OUT PVOID PnPControlData,
	IN ULONG PnPControlDataLength);

EXTERN_C NTSTATUS NtQueryDirectoryObject(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG Length,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestartScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtQueryVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FsInformation,
	IN ULONG Length,
	IN FSINFOCLASS FsInformationClass);

EXTERN_C NTSTATUS NtIsProcessInJob(
	IN HANDLE ProcessHandle,
	IN HANDLE JobHandle OPTIONAL);

EXTERN_C NTSTATUS NtSetContextThread(
	IN HANDLE ThreadHandle,
	IN PCONTEXT Context);

EXTERN_C NTSTATUS NtAlpcCreateSectionView(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_DATA_VIEW_ATTR ViewAttributes);

EXTERN_C NTSTATUS NtUnsubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtSetInformationVirtualMemory(
	IN HANDLE ProcessHandle,
	IN VIRTUAL_MEMORY_INFORMATION_CLASS VmInformationClass,
	IN ULONG_PTR NumberOfEntries,
	IN PMEMORY_RANGE_ENTRY VirtualAddresses,
	IN PVOID VmInformation,
	IN ULONG VmInformationLength);

EXTERN_C NTSTATUS NtDuplicateObject(
	IN HANDLE SourceProcessHandle,
	IN HANDLE SourceHandle,
	IN HANDLE TargetProcessHandle OPTIONAL,
	OUT PHANDLE TargetHandle OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Options);

EXTERN_C NTSTATUS NtResumeThread(
	IN HANDLE ThreadHandle,
	IN OUT PULONG PreviousSuspendCount OPTIONAL);

EXTERN_C NTSTATUS NtRenameKey(
	IN HANDLE KeyHandle,
	IN PUNICODE_STRING NewName);

EXTERN_C NTSTATUS NtFindAtom(
	IN PWSTR AtomName OPTIONAL,
	IN ULONG Length,
	OUT PUSHORT Atom OPTIONAL);

EXTERN_C NTSTATUS NtReplyWaitReceivePortEx(
	IN HANDLE PortHandle,
	OUT PULONG PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtCreateWnfStateName(
	OUT PCWNF_STATE_NAME StateName,
	IN WNF_STATE_NAME_LIFETIME NameLifetime,
	IN WNF_DATA_SCOPE DataScope,
	IN BOOLEAN PersistData,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN ULONG MaximumStateSize,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor);

EXTERN_C NTSTATUS NtFilterToken(
	IN HANDLE ExistingTokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtUnmapViewOfSection(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress);

EXTERN_C NTSTATUS NtResumeProcess(
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtSetInformationDebugObject(
	IN HANDLE DebugObject,
	IN DEBUGOBJECTINFOCLASS InformationClass,
	IN PVOID Information,
	IN ULONG InformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtCompareTokens(
	IN HANDLE FirstTokenHandle,
	IN HANDLE SecondTokenHandle,
	OUT PBOOLEAN Equal);

EXTERN_C NTSTATUS NtWaitForDebugEvent(
	IN HANDLE DebugObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL,
	OUT PVOID WaitStateChange);

EXTERN_C NTSTATUS NtSetUuidSeed(
	IN PUCHAR Seed);

EXTERN_C NTSTATUS NtClearEvent(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtAllocateLocallyUniqueId(
	OUT PLUID Luid);

EXTERN_C NTSTATUS NtCreateMutant(
	OUT PHANDLE MutantHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN BOOLEAN InitialOwner);

EXTERN_C NTSTATUS NtGetPlugPlayEvent(
	IN HANDLE EventHandle,
	IN PVOID Context OPTIONAL,
	OUT PPLUGPLAY_EVENT_BLOCK EventBlock,
	IN ULONG EventBufferSize);

EXTERN_C NTSTATUS NtListTransactions();

EXTERN_C NTSTATUS NtSetIoCompletionEx(
	IN HANDLE IoCompletionHandle,
	IN HANDLE IoCompletionPacketHandle,
	IN PVOID KeyContext OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	IN NTSTATUS IoStatus,
	IN ULONG_PTR IoStatusInformation);

EXTERN_C NTSTATUS NtAlpcAcceptConnectPort(
	OUT PHANDLE PortHandle,
	IN HANDLE ConnectionPortHandle,
	IN ULONG Flags,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL,
	IN PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ConnectionRequest,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ConnectionMessageAttributes OPTIONAL,
	IN BOOLEAN AcceptConnection);

EXTERN_C NTSTATUS NtOpenDirectoryObject(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtQuerySystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	OUT PVOID VariableValue,
	IN ULONG ValueLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message);

EXTERN_C NTSTATUS NtTestAlert();

EXTERN_C NTSTATUS NtAlpcCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PALPC_PORT_ATTRIBUTES PortAttributes OPTIONAL);

EXTERN_C NTSTATUS NtRollbackSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtSetEaFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_FULL_EA_INFORMATION EaBuffer,
	IN ULONG EaBufferSize);

EXTERN_C NTSTATUS NtOpenPrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtReadOnlyEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtQueryEvent(
	IN HANDLE EventHandle,
	IN EVENT_INFORMATION_CLASS EventInformationClass,
	OUT PVOID EventInformation,
	IN ULONG EventInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtOpenSymbolicLinkObject(
	OUT PHANDLE LinkHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCreateTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TIMER_TYPE TimerType);

EXTERN_C NTSTATUS NtQueryDefaultUILanguage(
	OUT PLANGID DefaultUILanguageId);

EXTERN_C NTSTATUS NtIsUILanguageComitted();

EXTERN_C NTSTATUS NtGetCurrentProcessorNumberEx(
	OUT PULONG ProcNumber OPTIONAL);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFileEx(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	IN DIRECTORY_NOTIFY_INFORMATION_CLASS DirectoryNotifyInformationClass OPTIONAL);

EXTERN_C NTSTATUS NtEnumerateValueKey(
	IN HANDLE KeyHandle,
	IN ULONG Index,
	IN KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	OUT PVOID KeyValueInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtGetDevicePowerState(
	IN HANDLE Device,
	OUT PDEVICE_POWER_STATE State);

EXTERN_C NTSTATUS NtProtectVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect);

EXTERN_C NTSTATUS NtDebugActiveProcess(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtMakePermanentObject(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtOpenThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtRaiseException(
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN BOOLEAN FirstChance);

EXTERN_C NTSTATUS NtQueryInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID ThreadInformation,
	IN ULONG ThreadInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtCompleteConnectPort(
	IN HANDLE PortHandle);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultList(
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_TYPE_LIST ObjectTypeList,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus);

EXTERN_C NTSTATUS NtSetBootEntryOrder(
	IN PULONG Ids,
	IN ULONG Count);

EXTERN_C NTSTATUS NtSetDefaultLocale(
	IN BOOLEAN UserProfile,
	IN LCID DefaultLocaleId);

EXTERN_C NTSTATUS NtAccessCheckByTypeResultListAndAuditAlarmByHandle(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN HANDLE ClientToken,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PULONG GenerateOnClose);

EXTERN_C NTSTATUS NtLoadHotPatch(
	IN PUNICODE_STRING HotPatchName,
	IN ULONG LoadFlag);

EXTERN_C NTSTATUS NtCreatePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtOpenTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN LPGUID TmIdentity OPTIONAL,
	IN ULONG OpenOptions OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PULONG RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValue(
	IN PUNICODE_STRING VariableName,
	IN PUNICODE_STRING Value);

EXTERN_C NTSTATUS NtQueryInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTION_INFORMATION_CLASS TransactionInformationClass,
	OUT PVOID TransactionInformation,
	IN ULONG TransactionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtReadRequestData(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG DataEntryIndex,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtSystemDebugControl(
	IN DEBUG_CONTROL_CODE Command,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCancelMessage(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PALPC_CONTEXT_ATTR MessageContext);

EXTERN_C NTSTATUS NtLockRegistryKey(
	IN HANDLE KeyHandle);

EXTERN_C NTSTATUS NtNotifyChangeMultipleKeys(
	IN HANDLE MasterKeyHandle,
	IN ULONG Count OPTIONAL,
	IN POBJECT_ATTRIBUTES SubordinateObjects OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtImpersonateAnonymousToken(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtUnlockFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key);

EXTERN_C NTSTATUS NtQueueApcThread(
	IN HANDLE ThreadHandle,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtAccessCheckByTypeAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN PSID PrincipalSelfSid OPTIONAL,
	IN ACCESS_MASK DesiredAccess,
	IN AUDIT_EVENT_TYPE AuditType,
	IN ULONG Flags,
	IN POBJECT_TYPE_LIST ObjectTypeList OPTIONAL,
	IN ULONG ObjectTypeListLength,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PULONG AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtResetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtQueueApcThreadEx(
	IN HANDLE ThreadHandle,
	IN HANDLE UserApcReserveHandle OPTIONAL,
	IN PKNORMAL_ROUTINE ApcRoutine,
	IN PVOID ApcArgument1 OPTIONAL,
	IN PVOID ApcArgument2 OPTIONAL,
	IN PVOID ApcArgument3 OPTIONAL);

EXTERN_C NTSTATUS NtClearAllSavepointsTransaction(
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtQueryWnfStateNameInformation(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID NameInfoClass,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PVOID InfoBuffer,
	IN ULONG InfoBufferSize);

EXTERN_C NTSTATUS NtRequestWakeupLatency(
	IN ULONG LatencyTime);

EXTERN_C NTSTATUS NtCreateKey(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtStartProfile(
	IN HANDLE ProfileHandle);

EXTERN_C NTSTATUS NtAlpcSendWaitReceivePort(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN PPORT_MESSAGE SendMessage OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES SendMessageAttributes OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage OPTIONAL,
	IN OUT PSIZE_T BufferLength OPTIONAL,
	IN OUT PALPC_MESSAGE_ATTRIBUTES ReceiveMessageAttributes OPTIONAL,
	IN PLARGE_INTEGER Timeout OPTIONAL);

EXTERN_C NTSTATUS NtOpenThreadTokenEx(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	IN ULONG HandleAttributes,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtSetInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	IN PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength);

EXTERN_C NTSTATUS NtQuerySystemInformationEx(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN PVOID InputBuffer,
	IN ULONG InputBufferLength,
	OUT PVOID SystemInformation OPTIONAL,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcImpersonateClientOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN PVOID Flags);

EXTERN_C NTSTATUS NtDisplayString(
	IN PUNICODE_STRING String);

EXTERN_C NTSTATUS NtSetDriverEntryOrder(
	IN PULONG Ids,
	IN PULONG Count);

EXTERN_C NTSTATUS NtQueryDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan);

EXTERN_C NTSTATUS NtCreateThreadEx(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	IN PVOID StartRoutine,
	IN PVOID Argument OPTIONAL,
	IN ULONG CreateFlags,
	IN SIZE_T ZeroBits,
	IN SIZE_T StackSize,
	IN SIZE_T MaximumStackSize,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtManagePartition(
	IN HANDLE TargetHandle,
	IN HANDLE SourceHandle,
	IN MEMORY_PARTITION_INFORMATION_CLASS PartitionInformationClass,
	IN OUT PVOID PartitionInformation,
	IN ULONG PartitionInformationLength);

EXTERN_C NTSTATUS NtQueryMutant(
	IN HANDLE MutantHandle,
	IN MUTANT_INFORMATION_CLASS MutantInformationClass,
	OUT PVOID MutantInformation,
	IN ULONG MutantInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtRestoreKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtReleaseWorkerFactoryWorker(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtSecureConnectPort(
	OUT PHANDLE PortHandle,
	IN PUNICODE_STRING PortName,
	IN PSECURITY_QUALITY_OF_SERVICE SecurityQos,
	IN OUT PPORT_SECTION_WRITE ClientView OPTIONAL,
	IN PSID RequiredServerSid OPTIONAL,
	IN OUT PPORT_SECTION_READ ServerView OPTIONAL,
	OUT PULONG MaxMessageLength OPTIONAL,
	IN OUT PVOID ConnectionInformation OPTIONAL,
	IN OUT PULONG ConnectionInformationLength OPTIONAL);

EXTERN_C NTSTATUS NtFlushVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtReadFileScatter(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtQuerySymbolicLinkObject(
	IN HANDLE LinkHandle,
	IN OUT PUNICODE_STRING LinkTarget,
	OUT PULONG ReturnedLength OPTIONAL);

EXTERN_C NTSTATUS NtTerminateProcess(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtQuerySecurityAttributesToken(
	IN HANDLE TokenHandle,
	IN PUNICODE_STRING Attributes OPTIONAL,
	IN ULONG NumberOfAttributes,
	OUT PVOID Buffer,
	IN ULONG Length,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtMapViewOfSectionEx(
	IN HANDLE SectionHandle,
	IN HANDLE ProcessHandle,
	IN OUT PLARGE_INTEGER SectionOffset,
	IN OUT PPVOID BaseAddress,
	IN OUT PSIZE_T ViewSize,
	IN ULONG AllocationType,
	IN ULONG Protect,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtAlpcCreatePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle OPTIONAL,
	IN SIZE_T SectionSize,
	OUT PHANDLE AlpcSectionHandle,
	OUT PSIZE_T ActualSectionSize);

EXTERN_C NTSTATUS NtSetInformationObject(
	IN HANDLE Handle,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
	IN PVOID ObjectInformation,
	IN ULONG ObjectInformationLength);

EXTERN_C NTSTATUS NtCreateThread(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	IN PCONTEXT ThreadContext,
	IN PUSER_STACK InitialTeb,
	IN BOOLEAN CreateSuspended);

EXTERN_C NTSTATUS NtAdjustGroupsToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN ResetToDefault,
	IN PTOKEN_GROUPS NewState OPTIONAL,
	IN ULONG BufferLength OPTIONAL,
	OUT PTOKEN_GROUPS PreviousState OPTIONAL,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtSetIntervalProfile(
	IN ULONG Interval,
	IN KPROFILE_SOURCE Source);

EXTERN_C NTSTATUS NtCallEnclave(
	IN PENCLAVE_ROUTINE Routine,
	IN PVOID Parameter,
	IN BOOLEAN WaitForThread,
	IN OUT PVOID ReturnValue OPTIONAL);

EXTERN_C NTSTATUS NtAccessCheckAndAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PVOID HandleId OPTIONAL,
	IN PUNICODE_STRING ObjectTypeName,
	IN PUNICODE_STRING ObjectName,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor,
	IN ACCESS_MASK DesiredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	IN BOOLEAN ObjectCreation,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus,
	OUT PBOOLEAN GenerateOnClose);

EXTERN_C NTSTATUS NtQueryInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass);

EXTERN_C NTSTATUS NtCreateToken(
	OUT PHANDLE TokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN TOKEN_TYPE TokenType,
	IN PLUID AuthenticationId,
	IN PLARGE_INTEGER ExpirationTime,
	IN PTOKEN_USER User,
	IN PTOKEN_GROUPS Groups,
	IN PTOKEN_PRIVILEGES Privileges,
	IN PTOKEN_OWNER Owner OPTIONAL,
	IN PTOKEN_PRIMARY_GROUP PrimaryGroup,
	IN PTOKEN_DEFAULT_DACL DefaultDacl OPTIONAL,
	IN PTOKEN_SOURCE TokenSource);

EXTERN_C NTSTATUS NtCancelIoFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtCommitTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Wait);

EXTERN_C NTSTATUS NtReadFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	OUT PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN BOOLEAN Flag,
	OUT ULONG SavePointId);

EXTERN_C NTSTATUS NtUmsThreadYield(
	IN PVOID SchedulerParam);

EXTERN_C NTSTATUS NtQueryWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	OUT PWNF_CHANGE_STAMP ChangeStamp,
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferSize);

EXTERN_C NTSTATUS NtFilterTokenEx(
	IN HANDLE TokenHandle,
	IN ULONG Flags,
	IN PTOKEN_GROUPS SidsToDisable OPTIONAL,
	IN PTOKEN_PRIVILEGES PrivilegesToDelete OPTIONAL,
	IN PTOKEN_GROUPS RestrictedSids OPTIONAL,
	IN ULONG DisableUserClaimsCount,
	IN PUNICODE_STRING UserClaimsToDisable OPTIONAL,
	IN ULONG DisableDeviceClaimsCount,
	IN PUNICODE_STRING DeviceClaimsToDisable OPTIONAL,
	IN PTOKEN_GROUPS DeviceGroupsToDisable OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedUserAttributes OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION RestrictedDeviceAttributes OPTIONAL,
	IN PTOKEN_GROUPS RestrictedDeviceGroups OPTIONAL,
	OUT PHANDLE NewTokenHandle);

EXTERN_C NTSTATUS NtEnumerateDriverEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtDeleteWnfStateName(
	IN PCWNF_STATE_NAME StateName);

EXTERN_C NTSTATUS NtWaitHighEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtDeleteAtom(
	IN USHORT Atom);

EXTERN_C NTSTATUS NtRemoveProcessDebug(
	IN HANDLE ProcessHandle,
	IN HANDLE DebugObjectHandle);

EXTERN_C NTSTATUS NtMarshallTransaction();

EXTERN_C NTSTATUS NtReplyWaitReplyPort(
	IN HANDLE PortHandle,
	IN OUT PPORT_MESSAGE ReplyMessage);

EXTERN_C NTSTATUS NtSetInformationThread(
	IN HANDLE ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	IN PVOID ThreadInformation,
	IN ULONG ThreadInformationLength);

EXTERN_C NTSTATUS NtSaveMergedKeys(
	IN HANDLE HighPrecedenceKeyHandle,
	IN HANDLE LowPrecedenceKeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtReplacePartitionUnit(
	IN PUNICODE_STRING TargetInstancePath,
	IN PUNICODE_STRING SpareInstancePath,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID BaseAddress,
	IN OUT PULONG RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS NtRecoverResourceManager(
	IN HANDLE ResourceManagerHandle);

EXTERN_C NTSTATUS NtSetQuotaInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_USER_QUOTA_INFORMATION Buffer,
	IN ULONG Length);

EXTERN_C NTSTATUS NtCallbackReturn(
	IN PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputLength,
	IN NTSTATUS Status);

EXTERN_C NTSTATUS NtDisableLastKnownGood();

EXTERN_C NTSTATUS NtQueryLicenseValue(
	IN PUNICODE_STRING ValueName,
	OUT PULONG Type OPTIONAL,
	OUT PVOID SystemData OPTIONAL,
	IN ULONG DataSize,
	OUT PULONG ResultDataSize);

EXTERN_C NTSTATUS NtTraceEvent(
	IN HANDLE TraceHandle,
	IN ULONG Flags,
	IN ULONG FieldSize,
	IN PVOID Fields);

EXTERN_C NTSTATUS NtAlertThreadByThreadId(
	IN ULONG ThreadId);

EXTERN_C NTSTATUS NtSetSystemEnvironmentValueEx(
	IN PUNICODE_STRING VariableName,
	IN LPGUID VendorGuid,
	IN PVOID Value OPTIONAL,
	IN ULONG ValueLength,
	IN ULONG Attributes);

EXTERN_C NTSTATUS NtWriteFileGather(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PFILE_SEGMENT_ELEMENT SegmentArray,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtQuerySecurityObject(
	IN HANDLE Handle,
	IN SECURITY_INFORMATION SecurityInformation,
	OUT PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN ULONG Length,
	OUT PULONG LengthNeeded);

EXTERN_C NTSTATUS NtAlpcDisconnectPort(
	IN HANDLE PortHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtEnableLastKnownGood();

EXTERN_C NTSTATUS NtDeletePrivateNamespace(
	IN HANDLE NamespaceHandle);

EXTERN_C NTSTATUS NtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS NtApphelpCacheControl(
	IN APPHELPCACHESERVICECLASS Service,
	IN PVOID ServiceData);

EXTERN_C NTSTATUS NtSetLowWaitHighEventPair(
	IN HANDLE EventPairHandle);

EXTERN_C NTSTATUS NtAdjustPrivilegesToken(
	IN HANDLE TokenHandle,
	IN BOOLEAN DisableAllPrivileges,
	IN PTOKEN_PRIVILEGES NewState OPTIONAL,
	IN ULONG BufferLength,
	OUT PTOKEN_PRIVILEGES PreviousState OPTIONAL,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetTimerResolution(
	IN ULONG DesiredResolution,
	IN BOOLEAN SetResolution,
	OUT PULONG CurrentResolution);

EXTERN_C NTSTATUS NtAlpcOpenSenderThread(
	OUT PHANDLE ThreadHandle,
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE PortMessage,
	IN ULONG Flags,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtRegisterProtocolAddressInformation(
	IN HANDLE ResourceManager,
	IN LPGUID ProtocolId,
	IN ULONG ProtocolInformationSize,
	IN PVOID ProtocolInformation,
	IN ULONG CreateOptions OPTIONAL);

EXTERN_C NTSTATUS NtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN ULONG BufferSize,
	OUT PULONG NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS NtSaveKeyEx(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle,
	IN ULONG Format);

EXTERN_C NTSTATUS NtRollbackRegistryTransaction(
	IN HANDLE RegistryHandle,
	IN BOOL Wait);

EXTERN_C NTSTATUS NtFsControlFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG FsControlCode,
	IN PVOID InputBuffer OPTIONAL,
	IN ULONG InputBufferLength,
	OUT PVOID OutputBuffer OPTIONAL,
	IN ULONG OutputBufferLength);

EXTERN_C NTSTATUS NtSubscribeWnfStateChange(
	IN PCWNF_STATE_NAME StateName,
	IN WNF_CHANGE_STAMP ChangeStamp OPTIONAL,
	IN ULONG EventMask,
	OUT PLARGE_INTEGER SubscriptionId OPTIONAL);

EXTERN_C NTSTATUS NtDeleteDriverEntry(
	IN ULONG Id);

EXTERN_C NTSTATUS NtSaveKey(
	IN HANDLE KeyHandle,
	IN HANDLE FileHandle);

EXTERN_C NTSTATUS NtQueryInformationTransactionManager(
	IN HANDLE TransactionManagerHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionManagerInformationClass,
	OUT PVOID TransactionManagerInformation,
	IN ULONG TransactionManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcImpersonateClientContainerOfPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE Message,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtQueryDebugFilterState(
	IN ULONG ComponentId,
	IN ULONG Level);

EXTERN_C NTSTATUS NtSetSecurityObject(
	IN HANDLE ObjectHandle,
	IN SECURITY_INFORMATION SecurityInformationClass,
	IN PSECURITY_DESCRIPTOR DescriptorBuffer);

EXTERN_C NTSTATUS NtCreateKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG TitleIndex,
	IN PUNICODE_STRING Class OPTIONAL,
	IN ULONG CreateOptions,
	IN HANDLE TransactionHandle,
	OUT PULONG Disposition OPTIONAL);

EXTERN_C NTSTATUS NtLoadEnclaveData(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN PVOID Buffer,
	IN SIZE_T BufferSize,
	IN ULONG Protect,
	IN PVOID PageInformation,
	IN ULONG PageInformationLength,
	OUT PSIZE_T NumberOfBytesWritten OPTIONAL,
	OUT PULONG EnclaveError OPTIONAL);

EXTERN_C NTSTATUS NtGetNextProcess(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN ULONG HandleAttributes,
	IN ULONG Flags,
	OUT PHANDLE NewProcessHandle);

EXTERN_C NTSTATUS NtQueryTimer(
	IN HANDLE TimerHandle,
	IN TIMER_INFORMATION_CLASS TimerInformationClass,
	OUT PVOID TimerInformation,
	IN ULONG TimerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtTerminateThread(
	IN HANDLE ThreadHandle,
	IN NTSTATUS ExitStatus);

EXTERN_C NTSTATUS NtGetMUIRegistryInfo(
	IN ULONG Flags,
	IN OUT PULONG DataSize,
	OUT PVOID SystemData);

EXTERN_C NTSTATUS NtQueryDefaultLocale(
	IN BOOLEAN UserProfile,
	OUT PLCID DefaultLocaleId);

EXTERN_C NTSTATUS NtLockFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PULARGE_INTEGER ByteOffset,
	IN PULARGE_INTEGER Length,
	IN ULONG Key,
	IN BOOLEAN FailImmediately,
	IN BOOLEAN ExclusiveLock);

EXTERN_C NTSTATUS NtAlpcDeleteResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ResourceId);

EXTERN_C NTSTATUS NtCreateProfileEx(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN SIZE_T ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN USHORT GroupCount,
	IN PGROUP_AFFINITY GroupAffinity);

EXTERN_C NTSTATUS NtQueryOpenSubKeys(
	IN POBJECT_ATTRIBUTES TargetKey,
	OUT PULONG HandleCount);

EXTERN_C NTSTATUS NtSetIRTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime OPTIONAL);

EXTERN_C NTSTATUS NtAllocateVirtualMemoryEx(
	IN HANDLE ProcessHandle,
	IN OUT PPVOID lpAddress,
	IN ULONG_PTR ZeroBits,
	IN OUT PSIZE_T pSize,
	IN ULONG flAllocationType,
	IN OUT PVOID DataBuffer OPTIONAL,
	IN ULONG DataCount);

EXTERN_C NTSTATUS NtCreatePrivateNamespace(
	OUT PHANDLE NamespaceHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PVOID BoundaryDescriptor);

EXTERN_C NTSTATUS NtRequestPort(
	IN HANDLE PortHandle,
	IN PPORT_MESSAGE RequestMessage);

EXTERN_C NTSTATUS NtOpenFile(
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions);

EXTERN_C NTSTATUS NtCreateWaitablePort(
	OUT PHANDLE PortHandle,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG MaxConnectionInfoLength,
	IN ULONG MaxMessageLength,
	IN ULONG MaxPoolUsage OPTIONAL);

EXTERN_C NTSTATUS NtOpenThreadToken(
	IN HANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN BOOLEAN OpenAsSelf,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtSetIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN ULONG CompletionKey,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN NTSTATUS CompletionStatus,
	IN ULONG NumberOfBytesTransfered);

EXTERN_C NTSTATUS NtReplyWaitReceivePort(
	IN HANDLE PortHandle,
	OUT PVOID PortContext OPTIONAL,
	IN PPORT_MESSAGE ReplyMessage OPTIONAL,
	OUT PPORT_MESSAGE ReceiveMessage);

EXTERN_C NTSTATUS NtFlushInstructionCache(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	IN ULONG Length);

EXTERN_C NTSTATUS NtGetCompleteWnfStateSubscription(
	IN PCWNF_STATE_NAME OldDescriptorStateName OPTIONAL,
	IN PLARGE_INTEGER OldSubscriptionId OPTIONAL,
	IN ULONG OldDescriptorEventMask OPTIONAL,
	IN ULONG OldDescriptorStatus OPTIONAL,
	OUT PWNF_DELIVERY_DESCRIPTOR NewDeliveryDescriptor,
	IN ULONG DescriptorSize);

EXTERN_C NTSTATUS NtSetInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	IN PVOID TokenInformation,
	IN ULONG TokenInformationLength);

EXTERN_C NTSTATUS NtShutdownSystem(
	IN SHUTDOWN_ACTION Action);

EXTERN_C NTSTATUS NtPrivilegedServiceAuditAlarm(
	IN PUNICODE_STRING SubsystemName,
	IN PUNICODE_STRING ServiceName,
	IN HANDLE ClientToken,
	IN PPRIVILEGE_SET Privileges,
	IN BOOLEAN AccessGranted);

EXTERN_C NTSTATUS NtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN ULONG MemoryInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetTimer(
	IN HANDLE TimerHandle,
	IN PLARGE_INTEGER DueTime,
	IN PTIMER_APC_ROUTINE TimerApcRoutine OPTIONAL,
	IN PVOID TimerContext OPTIONAL,
	IN BOOLEAN ResumeTimer,
	IN LONG Period OPTIONAL,
	OUT PBOOLEAN PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtAddDriverEntry(
	IN PEFI_DRIVER_ENTRY DriverEntry,
	OUT PULONG Id OPTIONAL);

EXTERN_C NTSTATUS NtOpenSection(
	OUT PHANDLE SectionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCompareSigningLevels(
	IN ULONG UnknownParameter1,
	IN ULONG UnknownParameter2);

EXTERN_C NTSTATUS NtReleaseCMFViewOwnership();

EXTERN_C NTSTATUS NtReplaceKey(
	IN POBJECT_ATTRIBUTES NewFile,
	IN HANDLE TargetHandle,
	IN POBJECT_ATTRIBUTES OldFile);

EXTERN_C NTSTATUS NtGetWriteWatch(
	IN HANDLE ProcessHandle,
	IN ULONG Flags,
	IN PVOID BaseAddress,
	IN ULONG RegionSize,
	OUT PULONG UserAddressArray,
	IN OUT PULONG EntriesInUserAddressArray,
	OUT PULONG Granularity);

EXTERN_C NTSTATUS NtDeleteWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID ExplicitScope OPTIONAL);

EXTERN_C NTSTATUS NtSinglePhaseReject(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtUnloadDriver(
	IN PUNICODE_STRING DriverServiceName);

EXTERN_C NTSTATUS NtCreateIRTimer(
	OUT PHANDLE TimerHandle,
	IN ACCESS_MASK DesiredAccess);

EXTERN_C NTSTATUS NtCreateTransactionManager(
	OUT PHANDLE TmHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN PUNICODE_STRING LogFileName OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN ULONG CommitStrength OPTIONAL);

EXTERN_C NTSTATUS NtFilterBootOption(
	IN FILTER_BOOT_OPTION_OPERATION FilterOperation,
	IN ULONG ObjectType,
	IN ULONG ElementType,
	IN PVOID SystemData OPTIONAL,
	IN ULONG DataSize);

EXTERN_C NTSTATUS NtWriteFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID Buffer,
	IN ULONG Length,
	IN PLARGE_INTEGER ByteOffset OPTIONAL,
	IN PULONG Key OPTIONAL);

EXTERN_C NTSTATUS NtNotifyChangeDirectoryFile(
	IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PFILE_NOTIFY_INFORMATION Buffer,
	IN ULONG Length,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree);

EXTERN_C NTSTATUS NtSetSystemPowerState(
	IN POWER_ACTION SystemAction,
	IN SYSTEM_POWER_STATE MinSystemState,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateJobObject(
	OUT PHANDLE JobHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtPulseEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtSavepointComplete(
	IN HANDLE TransactionHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationTransaction(
	IN HANDLE TransactionHandle,
	IN TRANSACTIONMANAGER_INFORMATION_CLASS TransactionInformationClass,
	IN PVOID TransactionInformation,
	IN ULONG TransactionInformationLength);

EXTERN_C NTSTATUS NtUpdateWnfStateData(
	IN PCWNF_STATE_NAME StateName,
	IN PVOID Buffer OPTIONAL,
	IN ULONG Length OPTIONAL,
	IN PCWNF_TYPE_ID TypeId OPTIONAL,
	IN PVOID ExplicitScope OPTIONAL,
	IN WNF_CHANGE_STAMP MatchingChangeStamp,
	IN ULONG CheckStamp);

EXTERN_C NTSTATUS NtCreateEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtCreatePartition(
	OUT PHANDLE PartitionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG PreferredNode);

EXTERN_C NTSTATUS NtSetTimerEx(
	IN HANDLE TimerHandle,
	IN TIMER_SET_INFORMATION_CLASS TimerSetInformationClass,
	IN OUT PVOID TimerSetInformation OPTIONAL,
	IN ULONG TimerSetInformationLength);

EXTERN_C NTSTATUS NtOpenSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtAlpcDeleteSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE ContextHandle);

EXTERN_C NTSTATUS NtCreateDebugObject(
	OUT PHANDLE DebugObjectHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtPrivilegeCheck(
	IN HANDLE ClientToken,
	IN OUT PPRIVILEGE_SET RequiredPrivileges,
	OUT PBOOLEAN Result);

EXTERN_C NTSTATUS NtLoadKey2(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtCreateSemaphore(
	OUT PHANDLE SemaphoreHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN LONG InitialCount,
	IN LONG MaximumCount);

EXTERN_C NTSTATUS NtCreateProfile(
	OUT PHANDLE ProfileHandle,
	IN HANDLE Process OPTIONAL,
	IN PVOID ProfileBase,
	IN ULONG ProfileSize,
	IN ULONG BucketSize,
	IN PULONG Buffer,
	IN ULONG BufferSize,
	IN KPROFILE_SOURCE ProfileSource,
	IN ULONG Affinity);

EXTERN_C NTSTATUS NtWaitLowEventPair(
	IN HANDLE EventHandle);

EXTERN_C NTSTATUS NtAlpcDeletePortSection(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN HANDLE SectionHandle);

EXTERN_C NTSTATUS NtAcquireProcessActivityReference();

EXTERN_C NTSTATUS NtAdjustTokenClaimsAndDeviceGroups(
	IN HANDLE TokenHandle,
	IN BOOLEAN UserResetToDefault,
	IN BOOLEAN DeviceResetToDefault,
	IN BOOLEAN DeviceGroupsResetToDefault,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewUserState OPTIONAL,
	IN PTOKEN_SECURITY_ATTRIBUTES_INFORMATION NewDeviceState OPTIONAL,
	IN PTOKEN_GROUPS NewDeviceGroupsState OPTIONAL,
	IN ULONG UserBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousUserState OPTIONAL,
	IN ULONG DeviceBufferLength,
	OUT PTOKEN_SECURITY_ATTRIBUTES_INFORMATION PreviousDeviceState OPTIONAL,
	IN ULONG DeviceGroupsBufferLength,
	OUT PTOKEN_GROUPS PreviousDeviceGroups OPTIONAL,
	OUT PULONG UserReturnLength OPTIONAL,
	OUT PULONG DeviceReturnLength OPTIONAL,
	OUT PULONG DeviceGroupsReturnBufferLength OPTIONAL);

EXTERN_C NTSTATUS NtNotifyChangeKey(
	IN HANDLE KeyHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG CompletionFilter,
	IN BOOLEAN WatchTree,
	OUT PVOID Buffer OPTIONAL,
	IN ULONG BufferSize,
	IN BOOLEAN Asynchronous);

EXTERN_C NTSTATUS NtWaitForSingleObject(
	IN HANDLE ObjectHandle,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER TimeOut OPTIONAL);

EXTERN_C NTSTATUS NtGetNlsSectionPtr(
	IN ULONG SectionType,
	IN ULONG SectionData,
	IN PVOID ContextData,
	OUT PVOID SectionPointer,
	OUT PULONG SectionSize);

EXTERN_C NTSTATUS NtQueryIoCompletion(
	IN HANDLE IoCompletionHandle,
	IN IO_COMPLETION_INFORMATION_CLASS IoCompletionInformationClass,
	OUT PVOID IoCompletionInformation,
	IN ULONG IoCompletionInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetVolumeInformationFile(
	IN HANDLE FileHandle,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN PVOID FileSystemInformation,
	IN ULONG Length,
	IN FSINFOCLASS FileSystemInformationClass);

EXTERN_C NTSTATUS NtCreateUserProcess(
	OUT PHANDLE ProcessHandle,
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK ProcessDesiredAccess,
	IN ACCESS_MASK ThreadDesiredAccess,
	IN POBJECT_ATTRIBUTES ProcessObjectAttributes OPTIONAL,
	IN POBJECT_ATTRIBUTES ThreadObjectAttributes OPTIONAL,
	IN ULONG ProcessFlags,
	IN ULONG ThreadFlags,
	IN PVOID ProcessParameters OPTIONAL,
	IN OUT PPS_CREATE_INFO CreateInfo,
	IN PPS_ATTRIBUTE_LIST AttributeList OPTIONAL);

EXTERN_C NTSTATUS NtCancelSynchronousIoFile(
	IN HANDLE ThreadHandle,
	IN PIO_STATUS_BLOCK IoRequestToCancel OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock);

EXTERN_C NTSTATUS NtPropagationFailed(
	IN HANDLE ResourceManagerHandle,
	IN ULONG RequestCookie,
	IN NTSTATUS PropStatus);

EXTERN_C NTSTATUS NtLoadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN POBJECT_ATTRIBUTES SourceFile,
	IN ULONG Flags,
	IN HANDLE TrustClassKey OPTIONAL,
	IN HANDLE Event OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	OUT PHANDLE RootHandle OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatus OPTIONAL);

EXTERN_C NTSTATUS NtQueryInformationResourceManager(
	IN HANDLE ResourceManagerHandle,
	IN RESOURCEMANAGER_INFORMATION_CLASS ResourceManagerInformationClass,
	OUT PVOID ResourceManagerInformation,
	IN ULONG ResourceManagerInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtSetInformationEnlistment(
	IN HANDLE EnlistmentHandle,
	IN ENLISTMENT_INFORMATION_CLASS EnlistmentInformationClass,
	IN PVOID EnlistmentInformation,
	IN ULONG EnlistmentInformationLength);

EXTERN_C NTSTATUS NtSetInformationProcess(
	IN HANDLE DeviceHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	IN PVOID ProcessInformation,
	IN ULONG Length);

EXTERN_C NTSTATUS NtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

EXTERN_C NTSTATUS NtRequestDeviceWakeup(
	IN HANDLE DeviceHandle);

EXTERN_C NTSTATUS NtSetSystemTime(
	IN PLARGE_INTEGER SystemTime,
	OUT PLARGE_INTEGER PreviousTime OPTIONAL);

EXTERN_C NTSTATUS NtMapUserPhysicalPages(
	IN PVOID VirtualAddress,
	IN PULONG NumberOfPages,
	IN PULONG UserPfnArray OPTIONAL);

EXTERN_C NTSTATUS NtClearSavepointTransaction(
	IN HANDLE TransactionHandle,
	IN ULONG SavePointId);

EXTERN_C NTSTATUS NtOpenKeyTransacted(
	OUT PHANDLE KeyHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE TransactionHandle);

EXTERN_C NTSTATUS NtQueryBootEntryOrder(
	OUT PULONG Ids OPTIONAL,
	IN OUT PULONG Count);

EXTERN_C NTSTATUS NtOpenProcessToken(
	IN HANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	OUT PHANDLE TokenHandle);

EXTERN_C NTSTATUS NtQueryFullAttributesFile(
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PFILE_NETWORK_OPEN_INFORMATION FileInformation);

EXTERN_C NTSTATUS NtCreateWaitCompletionPacket(
	OUT PHANDLE WaitCompletionPacketHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL);

EXTERN_C NTSTATUS NtQueryKey(
	IN HANDLE KeyHandle,
	IN KEY_INFORMATION_CLASS KeyInformationClass,
	OUT PVOID KeyInformation OPTIONAL,
	IN ULONG Length,
	OUT PULONG ResultLength);

EXTERN_C NTSTATUS NtQueryInformationPort(
	IN HANDLE PortHandle,
	IN PORT_INFORMATION_CLASS PortInformationClass,
	OUT PVOID PortInformation,
	IN ULONG Length,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreateResourceReserve(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN SIZE_T MessageSize,
	OUT PHANDLE ResourceId);

EXTERN_C NTSTATUS NtTranslateFilePath(
	IN PFILE_PATH InputFilePath,
	IN ULONG OutputType,
	OUT PFILE_PATH OutputFilePath OPTIONAL,
	IN OUT PULONG OutputFilePathLength OPTIONAL);

EXTERN_C NTSTATUS NtSetEvent(
	IN HANDLE EventHandle,
	OUT PULONG PreviousState OPTIONAL);

EXTERN_C NTSTATUS NtAlpcCreateSecurityContext(
	IN HANDLE PortHandle,
	IN ULONG Flags,
	IN OUT PALPC_SECURITY_ATTR SecurityAttribute);

EXTERN_C NTSTATUS NtAlertThread(
	IN HANDLE ThreadHandle);

EXTERN_C NTSTATUS NtSetInformationSymbolicLink(
	IN HANDLE Handle,
	IN ULONG Class,
	IN PVOID Buffer,
	IN ULONG BufferLength);

EXTERN_C NTSTATUS NtAssignProcessToJobObject(
	IN HANDLE JobHandle,
	IN HANDLE ProcessHandle);

EXTERN_C NTSTATUS NtQueryInformationAtom(
	IN USHORT Atom,
	IN ATOM_INFORMATION_CLASS AtomInformationClass,
	OUT PVOID AtomInformation,
	IN ULONG AtomInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS NtInitializeNlsFiles(
	OUT PVOID BaseAddress,
	OUT PLCID DefaultLocaleId,
	OUT PLARGE_INTEGER DefaultCasingTableSize);

EXTERN_C NTSTATUS NtReleaseMutant(
	IN HANDLE MutantHandle,
	OUT PULONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtWaitForWorkViaWorkerFactory(
	IN HANDLE WorkerFactoryHandle,
	OUT PVOID MiniPacket);

EXTERN_C NTSTATUS NtQuerySystemTime(
	OUT PLARGE_INTEGER SystemTime);

EXTERN_C NTSTATUS NtSetCachedSigningLevel(
	IN ULONG Flags,
	IN SE_SIGNING_LEVEL InputSigningLevel,
	IN PHANDLE SourceFiles,
	IN ULONG SourceFileCount,
	IN HANDLE TargetFile OPTIONAL);

EXTERN_C NTSTATUS NtCommitEnlistment(
	IN HANDLE EnlistmentHandle,
	IN PLARGE_INTEGER TmVirtualClock OPTIONAL);

EXTERN_C NTSTATUS NtCreateDirectoryObjectEx(
	OUT PHANDLE DirectoryHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ShadowDirectoryHandle,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtUnloadKeyEx(
	IN POBJECT_ATTRIBUTES TargetKey,
	IN HANDLE Event OPTIONAL);

EXTERN_C NTSTATUS NtReleaseSemaphore(
	IN HANDLE SemaphoreHandle,
	IN LONG ReleaseCount,
	OUT PLONG PreviousCount OPTIONAL);

EXTERN_C NTSTATUS NtAddAtomEx(
	IN PWSTR AtomName,
	IN ULONG Length,
	IN PRTL_ATOM Atom,
	IN ULONG Flags);

EXTERN_C NTSTATUS NtWorkerFactoryWorkerReady(
	IN HANDLE WorkerFactoryHandle);

EXTERN_C NTSTATUS NtOpenEventPair(
	OUT PHANDLE EventPairHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtQueryInformationToken(
	IN HANDLE TokenHandle,
	IN TOKEN_INFORMATION_CLASS TokenInformationClass,
	OUT PVOID TokenInformation,
	IN ULONG TokenInformationLength,
	OUT PULONG ReturnLength);

EXTERN_C NTSTATUS NtExtendSection(
	IN HANDLE SectionHandle,
	IN OUT PLARGE_INTEGER NewSectionSize);

EXTERN_C NTSTATUS NtAccessCheck(
	IN PSECURITY_DESCRIPTOR pSecurityDescriptor,
	IN HANDLE ClientToken,
	IN ACCESS_MASK DesiaredAccess,
	IN PGENERIC_MAPPING GenericMapping,
	OUT PPRIVILEGE_SET PrivilegeSet OPTIONAL,
	IN OUT PULONG PrivilegeSetLength,
	OUT PACCESS_MASK GrantedAccess,
	OUT PBOOLEAN AccessStatus);

EXTERN_C NTSTATUS NtCreateResourceManager(
	OUT PHANDLE ResourceManagerHandle,
	IN ACCESS_MASK DesiredAccess,
	IN HANDLE TmHandle,
	IN LPGUID RmGuid,
	IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
	IN ULONG CreateOptions OPTIONAL,
	IN PUNICODE_STRING Description OPTIONAL);

EXTERN_C NTSTATUS NtEnumerateBootEntries(
	OUT PVOID Buffer OPTIONAL,
	IN OUT PULONG BufferLength);

EXTERN_C NTSTATUS NtSignalAndWaitForSingleObject(
	IN HANDLE hObjectToSignal,
	IN HANDLE hObjectToWaitOn,
	IN BOOLEAN bAlertable,
	IN PLARGE_INTEGER dwMilliseconds OPTIONAL);

EXTERN_C NTSTATUS NtOpenSession(
	OUT PHANDLE SessionHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes);

EXTERN_C NTSTATUS NtCancelTimer2(
	IN HANDLE TimerHandle,
	IN PT2_CANCEL_PARAMETERS Parameters);

EXTERN_C NTSTATUS NtCompactKeys(
	IN ULONG Count,
	IN HANDLE KeyArray);

EXTERN_C NTSTATUS NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

