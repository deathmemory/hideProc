#pragma once

#define NT_SUCCESS(status)    ((NTSTATUS)(status)>=0)
typedef LONG    NTSTATUS;
typedef ULONG   ACCESS_MASK;
typedef ULONG    KPRIORITY ;
typedef DWORD    ACCESS_MASK ;

typedef enum _SYSTEM_INFORMATION_CLASS    //   Q S
{
	SystemBasicInformation,           // 00 Y N
	SystemProcessorInformation,        // 01 Y N
	SystemPerformanceInformation,       // 02 Y N
	SystemTimeOfDayInformation,        // 03 Y N
	SystemNotImplemented1,            // 04 Y N
	SystemProcessesAndThreadsInformation,  // 05 Y N
	SystemCallCounts,               // 06 Y N
	SystemConfigurationInformation,      // 07 Y N
	SystemProcessorTimes,            // 08 Y N
	SystemGlobalFlag,               // 09 Y Y
	SystemNotImplemented2,            // 10 Y N
	SystemModuleInformation,          // 11 Y N
	SystemLockInformation,            // 12 Y N
	SystemNotImplemented3,            // 13 Y N
	SystemNotImplemented4,            // 14 Y N
	SystemNotImplemented5,            // 15 Y N
	SystemHandleInformation,          // 16 Y N
	SystemObjectInformation,          // 17 Y N
	SystemPagefileInformation,         // 18 Y N
	SystemInstructionEmulationCounts,    // 19 Y N
	SystemInvalidInfoClass1,          // 20
	SystemCacheInformation,           // 21 Y Y
	SystemPoolTagInformation,          // 22 Y N
	SystemProcessorStatistics,         // 23 Y N
	SystemDpcInformation,            // 24 Y Y
	SystemNotImplemented6,            // 25 Y N
	SystemLoadImage,                // 26 N Y
	SystemUnloadImage,              // 27 N Y
	SystemTimeAdjustment,            // 28 Y Y
	SystemNotImplemented7,            // 29 Y N
	SystemNotImplemented8,            // 30 Y N
	SystemNotImplemented9,            // 31 Y N
	SystemCrashDumpInformation,        // 32 Y N
	SystemExceptionInformation,        // 33 Y N
	SystemCrashDumpStateInformation,     // 34 Y Y/N
	SystemKernelDebuggerInformation,     // 35 Y N
	SystemContextSwitchInformation,      // 36 Y N
	SystemRegistryQuotaInformation,      // 37 Y Y
	SystemLoadAndCallImage,           // 38 N Y
	SystemPrioritySeparation,          // 39 N Y
	SystemNotImplemented10,           // 40 Y N
	SystemNotImplemented11,           // 41 Y N
	SystemInvalidInfoClass2,          // 42
	SystemInvalidInfoClass3,          // 43
	SystemTimeZoneInformation,         // 44 Y N
	SystemLookasideInformation,        // 45 Y N
	SystemSetTimeSlipEvent,           // 46 N Y
	SystemCreateSession,             // 47 N Y
	SystemDeleteSession,             // 48 N Y
	SystemInvalidInfoClass4,          // 49
	SystemRangeStartInformation,        // 50 Y N
	SystemVerifierInformation,         // 51 Y Y
	SystemAddVerifier,              // 52 N Y
	SystemSessionProcessesInformation    // 53 Y N
} SYSTEM_INFORMATION_CLASS;
typedef NTSTATUS ( __stdcall *ZWQUERYSYSTEMINFORMATION)(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

typedef ULONG(__stdcall *RTLNTSTATUSTODOSERROR)(IN NTSTATUS Status);

typedef struct _SYSTEM_MODULE_INFORMATION  // Information Class 11
{
	ULONG  Reserved[2];
	PVOID  Base;
	ULONG  Size;
	ULONG  Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR  ImageName[256];
} SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION 
{
	//   ULONG ProcessId;//���̱�ʶ��
	//   UCHAR ObjectTypeNumber;//�򿪵Ķ��������
	//   UCHAR Flags;//������Ա�־
	//   USHORT Handle;//�����ֵ,�ڽ��̴򿪵ľ����Ψһ��ʶĳ�����         
	//   PVOID Object;//�����Ӧ��EPROCESS�ĵ�ַ
	//   ACCESS_MASK GrantedAccess;//�������ķ���Ȩ��
	USHORT dwPid;
	USHORT CreatorBackTraceIndex;
	BYTE   ObjType;
	BYTE   HandleAttributes;
	USHORT HndlOffset;
	DWORD  dwKeObject;
	ULONG  GrantedAccess;

} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX 
{
	ULONG NumberOfHandles;            //�����Ŀ
	SYSTEM_HANDLE_INFORMATION Information[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

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
	ULONG          NextEntryDelta;          //���ɽṹ���е�ƫ������
	ULONG          ThreadCount;             //�߳���Ŀ��
	ULONG          Reserved1[6];           
	LARGE_INTEGER CreateTime;              //����ʱ�䣻
	LARGE_INTEGER UserTime;                //�û�ģʽ(Ring 3)��CPUʱ�䣻
	LARGE_INTEGER KernelTime;              //�ں�ģʽ(Ring 0)��CPUʱ�䣻
	UNICODE_STRING ProcessName;             //�������ƣ�
	KPRIORITY      BasePriority;            //��������Ȩ��
	ULONG          ProcessId;               //���̱�ʶ����
	ULONG          InheritedFromProcessId; //�����̵ı�ʶ����
	ULONG          HandleCount;             //�����Ŀ��
	ULONG          Reserved2[2];
	VM_COUNTERS    VmCounters;              //����洢���Ľṹ��
	IO_COUNTERS    IoCounters;              //IO�����ṹ�� Windows 2000 only
	//SYSTEM_THREADS Threads[1];              //��������̵߳Ľṹ���飻
}SYSTEM_PROCESSES,*PSYSTEM_PROCESSES;

typedef NTSTATUS (WINAPI* lpZwQuerySystemInformation)(
	__in          DWORD  SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	);

NTSTATUS WINAPI ZwQuerySystemInformationFack(
	__in          SYSTEM_INFORMATION_CLASS SystemInformationClass,
	__in	      PVOID SystemInformation,
	__in          ULONG SystemInformationLength,
	__out_opt     PULONG ReturnLength
	);

typedef BOOL (WINAPI *lpCreateProcessInternalW)(HANDLE hToken,
					   LPCWSTR lpApplicationName,
					   LPWSTR lpCommandLine,
					   LPSECURITY_ATTRIBUTES lpProcessAttributes,
					   LPSECURITY_ATTRIBUTES lpThreadAttributes,
					   BOOL bInheritHandles,
					   DWORD dwCreationFlags,
					   LPVOID lpEnvironment,
					   LPCWSTR lpCurrentDirectory,
					   LPSTARTUPINFOW lpStartupInfo,
					   LPPROCESS_INFORMATION lpProcessInformation,
					   PHANDLE hNewToken);

BOOL WINAPI CreateProcessInternalWFack(HANDLE hToken,
					   LPCWSTR lpApplicationName,
					   LPWSTR lpCommandLine,
					   LPSECURITY_ATTRIBUTES lpProcessAttributes,
					   LPSECURITY_ATTRIBUTES lpThreadAttributes,
					   BOOL bInheritHandles,
					   DWORD dwCreationFlags,
					   LPVOID lpEnvironment,
					   LPCWSTR lpCurrentDirectory,
					   LPSTARTUPINFOW lpStartupInfo,
					   LPPROCESS_INFORMATION lpProcessInformation,
					   PHANDLE hNewToken);


BOOL InstallHook2();
void InjectProcess(HANDLE hProcess, LPCTSTR lpszDll);