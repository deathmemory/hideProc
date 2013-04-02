#pragma once

typedef struct _SYSTEM_BASIC_INFORMATION {
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
	BYTE Reserved1[312];
} SYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	BYTE Reserved1[48];
} SYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	PVOID Reserved2[3];
	HANDLE UniqueProcessId;
	PVOID Reserved3;
	ULONG HandleCount;
	BYTE Reserved4[4];
	PVOID Reserved5[11];
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *LPSYSTEM_PROCESS_INFORMATION;

typedef LONG    NTSTATUS;
typedef ULONG   ACCESS_MASK;
typedef ULONG    KPRIORITY ;
typedef DWORD    ACCESS_MASK ;

#define NT_SUCCESS(status)          ((NTSTATUS)(status)>=0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#define STATUS_ACCESS_DENIED        ((NTSTATUS)0xC0000022L)

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation,                // 0 Y N
	SystemProcessorInformation,            // 1 Y N
	SystemPerformanceInformation,        // 2 Y N
	SystemTimeOfDayInformation,            // 3 Y N
	SystemNotImplemented1,                // 4 Y N
	SystemProcessesAndThreadsInformation, // 5 Y N
	SystemCallCounts,                    // 6 Y N
	SystemConfigurationInformation,        // 7 Y N
	SystemProcessorTimes,                // 8 Y N
	SystemGlobalFlag,                    // 9 Y Y
	SystemNotImplemented2,                // 10 Y N
	SystemModuleInformation,            // 11 Y N
	SystemLockInformation,                // 12 Y N
	SystemNotImplemented3,                // 13 Y N
	SystemNotImplemented4,                // 14 Y N
	SystemNotImplemented5,                // 15 Y N
	SystemHandleInformation,            // 16 Y N
	SystemObjectInformation,            // 17 Y N
	SystemPagefileInformation,            // 18 Y N
	SystemInstructionEmulationCounts,    // 19 Y N
	SystemInvalidInfoClass1,            // 20
	SystemCacheInformation,                // 21 Y Y
	SystemPoolTagInformation,            // 22 Y N
	SystemProcessorStatistics,            // 23 Y N
	SystemDpcInformation,                // 24 Y Y
	SystemNotImplemented6,                // 25 Y N
	SystemLoadImage,                    // 26 N Y
	SystemUnloadImage,                    // 27 N Y
	SystemTimeAdjustment,                // 28 Y Y
	SystemNotImplemented7,                // 29 Y N
	SystemNotImplemented8,                // 30 Y N
	SystemNotImplemented9,                // 31 Y N
	SystemCrashDumpInformation,            // 32 Y N
	SystemExceptionInformation,            // 33 Y N
	SystemCrashDumpStateInformation,    // 34 Y Y/N
	SystemKernelDebuggerInformation,    // 35 Y N
	SystemContextSwitchInformation,        // 36 Y N
	SystemRegistryQuotaInformation,        // 37 Y Y
	SystemLoadAndCallImage,                // 38 N Y
	SystemPrioritySeparation,            // 39 N Y
	SystemNotImplemented10,                // 40 Y N
	SystemNotImplemented11,                // 41 Y N
	SystemInvalidInfoClass2,            // 42
	SystemInvalidInfoClass3,            // 43
	SystemTimeZoneInformation,            // 44 Y N
	SystemLookasideInformation,            // 45 Y N
	SystemSetTimeSlipEvent,                // 46 N Y
	SystemCreateSession,                // 47 N Y
	SystemDeleteSession,                // 48 N Y
	SystemInvalidInfoClass4,            // 49
	SystemRangeStartInformation,        // 50 Y N
	SystemVerifierInformation,            // 51 Y Y
	SystemAddVerifier,                    // 52 N Y
	SystemSessionProcessesInformation    // 53 Y N
} SYSTEM_INFORMATION_CLASS;

typedef struct _VM_COUNTERS {
	ULONG PeakVirtualSize;
	ULONG VirtualSize;
	ULONG PageFaultCount;
	ULONG PeakWorkingSetSize;
	ULONG WorkingSetSize;
	ULONG QuotaPeakPagedPoolUsage;
	ULONG QuotaPagedPoolUsage;
	ULONG QuotaPeakNonPagedPoolUsage;
	ULONG QuotaNonPagedPoolUsage;
	ULONG PagefileUsage;
	ULONG PeakPagefileUsage;
} VM_COUNTERS, *PVM_COUNTERS;

typedef struct _SYSTEM_PROCESSES
{
	ULONG          NextEntryDelta;          //构成结构序列的偏移量；
	ULONG          ThreadCount;             //线程数目；
	ULONG          Reserved1[6];           
	LARGE_INTEGER CreateTime;              //创建时间；
	LARGE_INTEGER UserTime;                //用户模式(Ring 3)的CPU时间；
	LARGE_INTEGER KernelTime;              //内核模式(Ring 0)的CPU时间；
	UNICODE_STRING ProcessName;             //进程名称；
	KPRIORITY      BasePriority;            //进程优先权；
	ULONG          ProcessId;               //进程标识符；
	ULONG          InheritedFromProcessId; //父进程的标识符；
	ULONG          HandleCount;             //句柄数目；
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;              //虚拟存储器的结构；
	IO_COUNTERS    IoCounters;              //IO计数结构； Windows 2000 only
	//SYSTEM_THREADS Threads[1];              //进程相关线程的结构数组；
}SYSTEM_PROCESSES,*PSYSTEM_PROCESSES;

typedef struct
_SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION {
	BYTE Reserved1[24];
} SYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION {
	BYTE Reserved1[16];
} SYSTEM_EXCEPTION_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	PVOID Reserved1;
} SYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION {
	BYTE Reserved1[32];
} SYSTEM_LOOKASIDE_INFORMATION;

void InstallHook();

typedef NTSTATUS (WINAPI* lpZwQuerySystemInformation)(
	__in          DWORD  SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	);

NTSTATUS WINAPI ZwQuerySystemInformationFack(
	__in          DWORD SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	);

typedef HANDLE (WINAPI* lpCreateFileW)(
						 __in          LPCTSTR lpFileName,
						 __in          DWORD dwDesiredAccess,
						 __in          DWORD dwShareMode,
						 __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
						 __in          DWORD dwCreationDisposition,
						 __in          DWORD dwFlagsAndAttributes,
						 __in          HANDLE hTemplateFile
						 );

HANDLE WINAPI CreateFileWFack(
						 __in          LPCTSTR lpFileName,
						 __in          DWORD dwDesiredAccess,
						 __in          DWORD dwShareMode,
						 __in          LPSECURITY_ATTRIBUTES lpSecurityAttributes,
						 __in          DWORD dwCreationDisposition,
						 __in          DWORD dwFlagsAndAttributes,
						 __in          HANDLE hTemplateFile
						 );

typedef LONG (WINAPI *lpRegQueryValueExW)(
							__in          HKEY hKey,
							__in          LPCTSTR lpValueName,
							LPDWORD lpReserved,
							__out         LPDWORD lpType,
							__out         LPBYTE lpData,
							__in      LPDWORD lpcbData
							);

LONG WINAPI RegQueryValueExWFack(
							__in          HKEY hKey,
							__in          LPCTSTR lpValueName,
							LPDWORD lpReserved,
							__out         LPDWORD lpType,
							__out         LPBYTE lpData,
							__in      LPDWORD lpcbData
							);

