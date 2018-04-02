#include "pedef.h"
typedef ULONG DWORD, *PDWORD, **PPDWORD;
typedef UCHAR BYTE, *PBYTE, **PPBYTE;
typedef USHORT WORD, *PWORD;

#define MAX_THREAD_CNT 10

#define SEC_IMAGE    0x01000000
#define MAX_EA_NAME_LEN    256  

#define MAX_EA_VALUE_LEN 65536  

#define EA_BUFSIZ (sizeof (FILE_FULL_EA_INFORMATION) + MAX_EA_NAME_LEN + MAX_EA_VALUE_LEN)  
#define NEXT_FEA(p) ((PFILE_FULL_EA_INFORMATION) (p->NextEntryOffset?(char *)p+p->NextEntryOffset:NULL))  
	
#define ROUND_OFFSET(a,b,r)    (((PBYTE)(b) - (PBYTE)(a) + ((r) - 1)) & ~((r) - 1))
#define ROUND_POS(b, a, r)    (((PBYTE)(a)) + ROUND_OFFSET(a, b, r))

typedef struct _VS_FIXEDFILEINFO { 
  DWORD dwSignature; 
  DWORD dwStrucVersion; 
  DWORD dwFileVersionMS; 
  DWORD dwFileVersionLS; 
  DWORD dwProductVersionMS; 
  DWORD dwProductVersionLS; 
  DWORD dwFileFlagsMask; 
  DWORD dwFileFlags; 
  DWORD dwFileOS; 
  DWORD dwFileType; 
  DWORD dwFileSubtype; 
  DWORD dwFileDateMS; 
  DWORD dwFileDateLS; 
} VS_FIXEDFILEINFO, *PVS_FIXEDFILEINFO;
typedef struct _VS_VERSIONINFO
{
    WORD  wLength;
    WORD  wValueLength;
    WORD  wType;
    WCHAR szKey[1];
    WORD  Padding1[1];
    VS_FIXEDFILEINFO Value;
    WORD  Padding2[1];
    WORD  Children[1];
}VS_VERSIONINFO, *PVS_VERSIONINFO;


void WPOFF();
void WPON();

NTSTATUS WriteFileRes(PCWSTR filename,PVOID buf,ULONG length, WORD major, WORD minor );
NTSTATUS WriteRegister( PCWSTR keyPath, PCWSTR displayName, DWORD dwErrorControl, PCWSTR imagePath, DWORD dwStart, DWORD dwType );
PIMAGE_RESOURCE_DATA_ENTRY GetVersionInfoEntry( PIMAGE_RESOURCE_DIRECTORY pRootRec );

typedef struct _LDR_DATA_TABLE_ENTRY
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     ULONG Flags;
     WORD LoadCount;
     WORD TlsIndex;
     union
     {
          LIST_ENTRY HashLinks;
          struct
          {
               PVOID SectionPointer;
               ULONG CheckSum;
          };
     };
     union
     {
          ULONG TimeDateStamp;
          PVOID LoadedImports;
     };
     PVOID EntryPointActivationContext;
     PVOID PatchInformation;
     LIST_ENTRY ForwarderLinks;
     LIST_ENTRY ServiceTagLinks;
     LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;


typedef struct _SYSTEM_MODULE {
  ULONG                Reserved1;
  ULONG                Reserved2;
  PVOID                ImageBaseAddress;
  ULONG                ImageSize;
  ULONG                Flags;
  USHORT                Id;
  USHORT                  Rank;
  USHORT                  w018;
  USHORT                 NameOffset;
  CHAR                Name[MAXIMUM_FILENAME_LENGTH];
}SYSTEM_MODULE, *PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
  ULONG                ModulesCount;
  SYSTEM_MODULE        Modules[0];
}SYSTEM_MODULE_INFORMATION, *PSYSTEM_MODULE_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation,
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInfo,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, *PSYSTEM_INFORMATION_CLASS;

extern
NTSYSAPI 
NTSTATUS
NTAPI
ZwQuerySystemInformation(
  IN ULONG 				  SystemInformationClass,
  OUT PVOID               SystemInformation,
  IN ULONG                SystemInformationLength,
  OUT PULONG              ReturnLength OPTIONAL );



extern
PVOID
RtlImageDirectoryEntryToData (
    IN PVOID Base,
    IN BOOLEAN MappedAsImage,
    IN USHORT DirectoryEntry,
    OUT PULONG Size);

extern ULONG NtBuildNumber;

extern POBJECT_TYPE *IoDriverObjectType;
NTKERNELAPI
NTSTATUS
ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID *Object
					   );

/*
extern
NTKERNELAPI
NTSTATUS
CmUnRegisterCallback(
    IN LARGE_INTEGER  Cookie
    );

*/


typedef enum
{
	PROCESS_LINK_OFFSET,
	PROCESS_THREADLISTHEAD_OFFSET,
	THREAD_LISTENTRY_OFFSET,
	ASPHKSTART_OFFSET,
	DESKTOP_OFFSET,
	DESKHKSTART_OFFSET,

	WIN32THREAD_PROCESSINFO_OFFSET,
	PROCESSINFO_MODLIST_OFFSET,
	PEB_PROCESSPARAMETERS_OFFSET,
	PROCESS_PARAMETERS_IMAGEPATHNAME_BUFFER_OFFSET,
	THREAD_START_ROUTINE_OFFSET,
	THREAD_TEB_OFFSET,
	THREAD_PRIORITY_OFFSET,
	THREAD_WIN32_START_ROUTINE_OFFSET,
}OFFSET_TYPE;

ULONG GetPlantformDependentInfo( ULONG uFlags );//获取不同平台的指定偏移

PEPROCESS GetSystemEProcess();

typedef struct _SYSTEM_THREAD_INFO
{
	HANDLE hThread;
	DWORD dwStartAddr;
}SYSTEM_THREAD_INFO, *PSYSTEM_THREAD_INFO;

UCHAR *
PsGetProcessImageFileName( IN PEPROCESS Process);
PVOID MapVirtualAddress(PVOID VirtualAddress, ULONG Length, PMDL *lpMdlAddr);
void UnMapVirtualAddress(PMDL MemoryDescriptorList);

PVOID GetFuncAddrFromExportTable( char *szModuleName, PANSI_STRING pstFuncName, PVOID HookFuncAddr );
PVOID GetFuncAddrFromModuleExportTable( PVOID pModuleBase, PANSI_STRING pstFuncName, PVOID HookFuncAddr, PDWORD pFuncBaseAddr );
BOOLEAN RestoreHook( PVOID pHookAddress, PVOID OriCodeBuffer, DWORD dwLen );

BOOLEAN GetKernelModuleInfo( char *lpKernelModuleName, PDWORD lpModuleBase, PDWORD lpModuleSize, char *lpModulePath );//获取指定内核模块的基地址、大小、路径

typedef
NTSTATUS
(NTAPI *PZWQUERYSYSTEMINFORMATION)(
ULONG SystemInformationClass,
PVOID SystemInformation,
ULONG SystemInformationLength,
PULONG ReturnLength OPTIONAL
);

void HideDriverModuleList( PDRIVER_OBJECT pDriverObject );
void HideDriverPe( PDRIVER_OBJECT pDriverObject );
//获取load_image回调数组地址
PVOID GetLoadImageNotifyArrayBase();
PVOID GetLoadImageNotifyAddr( PVOID pPsLoadImageNotifyArray, PVOID pNotifyAddr );

BOOLEAN IsCmpRegisterCallbackAddrExist( PVOID pCallbackAddr );
BOOLEAN IsIoTimerAddrExist( PVOID pIoTimer );
BOOLEAN IsLoadImageNotifyAddrExist( PVOID pNotifyAddr );
BOOLEAN IsSystemThreadExist( PVOID pStartRoutine );
PVOID GetShutdownPacketBaseAddr();
PVOID GetIoTimerQueueHeader();
PVOID GetCmpCallbackListHeader();

typedef struct _SHUTDOWN_PACKET {
    LIST_ENTRY ListEntry;
    PDEVICE_OBJECT DeviceObject;
} SHUTDOWN_PACKET, *PSHUTDOWN_PACKET;
BOOLEAN IsShowdownExist( PDEVICE_OBJECT pDeviceObject );
VOID GetSysFile( PUNICODE_STRING pRegisterPath, PUNICODE_STRING pKey, PWSTR *pKeyValue );
PVOID GetSysBuffer( PCWSTR pSysPath, PDWORD pdwSize );
NTSTATUS GetSoftVersion( PVOID pFileData, PWORD majorVer, PWORD minorVer );
NTSTATUS MapPe( PCWSTR path, PWORD majorVer, PWORD minorVer );
BOOLEAN GetDriverBaseInfo( IN PWCHAR pszName, OUT DWORD* pnBasePtr, OUT DWORD* pnSize );//根据驱动对象名获取驱动模块地址、大小

