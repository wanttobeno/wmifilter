#include <ntifs.h>

#include "funclib.h"
#include "pedef.h"

DWORD g_dwCr0 = 0;

//内存读写开关
void WPOFF()
{
	DWORD dwRegTag = 0;
	_asm
	{
		cli
		push eax
		mov eax,cr0
		mov dwRegTag,eax
		and eax, not 10000h
		mov cr0,eax
		pop eax
	}
	g_dwCr0 = dwRegTag;
	
}

void WPON()
{
	_asm
	{
		push eax
		mov eax,g_dwCr0
		//mov eax,cr0
		//or eax,10000h
		mov cr0,eax
		sti
		pop eax
	}
}


//获取不同平台结构偏移
ULONG GetPlantformDependentInfo( ULONG uFlags )
{
	ULONG uCurrent_Build;
	ULONG uOffset = 0;

	//获取版本号
	PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );

	switch( uFlags )
	{

	case PROCESS_LINK_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x088;
		if( uCurrent_Build >= 7200 ) uOffset = 0x0b8;
		break;
	case PROCESS_THREADLISTHEAD_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x190;
		if( uCurrent_Build >= 7200 ) uOffset = 0x188; 
		break;
	case THREAD_LISTENTRY_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x22c;
		if( uCurrent_Build >= 7200 ) uOffset = 0x268;
		break;
	
	case ASPHKSTART_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x0F8;
		if( uCurrent_Build >= 7200 ) uOffset = 0x19c;
		break;

	case DESKTOP_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x040;
		if( uCurrent_Build >= 7200 ) uOffset = 0x0cc;
		break;
	case DESKHKSTART_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x014;
		if( uCurrent_Build >= 7200 ) uOffset = 0x014;
		break;

	case WIN32THREAD_PROCESSINFO_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x02c;
		if( uCurrent_Build >= 7200 ) uOffset = 0x0B8;
		break;
	case PROCESSINFO_MODLIST_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x0a8;
		if( uCurrent_Build >= 7200 ) uOffset = 0x0C0;
		break;
	case PEB_PROCESSPARAMETERS_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x010;
		if( uCurrent_Build >= 7200 ) uOffset = 0x010;
		break;
	case PROCESS_PARAMETERS_IMAGEPATHNAME_BUFFER_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x03C;
		if( uCurrent_Build >= 7200 ) uOffset = 0x03C;
		break;
	case THREAD_START_ROUTINE_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x8;
		if( uCurrent_Build >= 7200 ) uOffset = 0x50;
		break;
	case THREAD_WIN32_START_ROUTINE_OFFSET:
		if( uCurrent_Build == 2600 ) uOffset = 0x228;
		if( uCurrent_Build >= 7200 ) uOffset = 0x260;
		break; 

		
	}

	return uOffset;
}


//获取系统进程内核对象
PEPROCESS GetSystemEProcess()
{
	PEPROCESS pPreEProcess = NULL;
	PEPROCESS pCurEProcess = NULL;
	UCHAR *pImageName = NULL;
	DWORD dwProcessLinkOffset = GetPlantformDependentInfo( PROCESS_LINK_OFFSET );

	pCurEProcess = PsGetCurrentProcess();
	pPreEProcess = pCurEProcess;
	do
	{
		if( MmIsAddressValid(pCurEProcess) )
			pImageName = PsGetProcessImageFileName( pCurEProcess );
		if( 0 == _strnicmp( pImageName, "System", strlen("System") ) )
		{
			return pCurEProcess;
		}
		if( MmIsAddressValid((PDWORD)((DWORD)pCurEProcess+dwProcessLinkOffset+4)) )
		{
			pCurEProcess = (PEPROCESS)( *(PDWORD)((DWORD)pCurEProcess+dwProcessLinkOffset+4) - dwProcessLinkOffset );
		}
		else
			break;
	
	}
	while ( pPreEProcess != pCurEProcess );

	return NULL;
	
}


//hook
PVOID GetFuncAddrFromExportTable( char *szModuleName, PANSI_STRING pstFuncName, PVOID HookFuncAddr )
{
	PVOID lpFuncBase = NULL;
	DWORD dwFuncBaseAddr = 0;
	DWORD lpModuleBase = 0;
	DWORD dwModuleSize = 0;
	char szModulePath[256] = {0};

	//获取模块信息
	BOOLEAN bFind = GetKernelModuleInfo( szModuleName, &lpModuleBase, &dwModuleSize, szModulePath );
	if( bFind )
	{
		lpFuncBase = GetFuncAddrFromModuleExportTable( (PVOID)(lpModuleBase), pstFuncName, HookFuncAddr, &dwFuncBaseAddr );
	}


	return lpFuncBase;

}


//////////////////////////////////////////////////////////////////////////
// 名称: GetDriverBaseInfo
// 说明: 根据驱动名称获取驱动对象信息: 驱动基址,驱动的大小
// 备注: 
//////////////////////////////////////////////////////////////////////////
BOOLEAN GetDriverBaseInfo( IN PWCHAR pszName, OUT DWORD* pnBasePtr, OUT DWORD* pnSize )
{
    UNICODE_STRING uniName;
    RtlInitUnicodeString( &uniName, pszName );

    PFILE_OBJECT pFileObject;
    PDEVICE_OBJECT pDeviceObject;

    // 获取设备指针
    NTSTATUS status = IoGetDeviceObjectPointer( &uniName, FILE_READ_DATA, &pFileObject, &pDeviceObject );
    if ( !NT_SUCCESS(status) )
        return FALSE;

    PDRIVER_OBJECT pDriverObj = pDeviceObject->DriverObject;

    // 返回设备基址和设备大小
    *pnBasePtr = (ULONG)pDriverObj->DriverStart;
    *pnSize = pDriverObj->DriverSize;

    ObDereferenceObject( pFileObject );
    return TRUE;
}

//获取指定内核模块的大小、基地址
BOOLEAN GetKernelModuleInfo( char *lpKernelModuleName, PDWORD lpModuleBase, PDWORD lpModuleSize, char *lpModulePath )
{
	PVOID lpBuffer = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	DWORD dwBufferSize = 4096;
	

	PSYSTEM_MODULE_INFORMATION pstSystemModuleInfo = NULL;
	DWORD dwKernelModuleCnt = 0;
	DWORD dwIndex = 0;
	
	UNICODE_STRING stFuncName1 = {0};
	PZWQUERYSYSTEMINFORMATION pZwQuerySystemInformation = NULL;
	
	RtlInitUnicodeString( &stFuncName1, L"ZwQuerySystemInformation" );
	pZwQuerySystemInformation = (PZWQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&stFuncName1);
	
	do
	{
		DWORD dwRet = 0;
		if( lpBuffer != NULL )
			ExFreePoolWithTag( lpBuffer, 0x206B6444 );
		lpBuffer = ExAllocatePoolWithTag( NonPagedPool, dwBufferSize, 0x206B6444 );
		if( lpBuffer == NULL )
		{
			return FALSE;
		}
		
		Status = pZwQuerySystemInformation( SystemModuleInformation, lpBuffer, dwBufferSize, &dwRet );
		if( !NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH )
		{
			ExFreePoolWithTag( lpBuffer, 0x206B6444 );
			return FALSE;
		}
		
		dwBufferSize += 4096;
	}while( !NT_SUCCESS(Status) );
	

	//已经获得系统模块列表,搜索指定模块的基地址、大小
	pstSystemModuleInfo = (PSYSTEM_MODULE_INFORMATION)lpBuffer;

	//如果未指定模块名，直接返回第一个模块基地址、大小
	if( lpKernelModuleName == NULL )
	{
    strcpy( lpModulePath, "\\??\\c:\\Windows\\System32\\" );
		strcat( lpModulePath, (char*)((DWORD)(pstSystemModuleInfo->Modules[dwIndex].Name) + (DWORD)(pstSystemModuleInfo->Modules[dwIndex].NameOffset)) );
    //strcpy( g_szSystemModuleName, (char*)((DWORD)(pstSystemModuleInfo->Modules[dwIndex].Name) + (DWORD)(pstSystemModuleInfo->Modules[dwIndex].NameOffset)) );
     //GetKernelModuleType();
		*lpModuleBase = (DWORD)pstSystemModuleInfo->Modules[0].ImageBaseAddress;
		*lpModuleSize = pstSystemModuleInfo->Modules[0].ImageSize;

		KdPrint(("模块路径:%s,基地址：%x，大小：%d\n", lpModulePath, *lpModuleBase, *lpModuleSize ));
		ExFreePoolWithTag( lpBuffer, 0x206B6444 );
		
		return TRUE;
	}

	
	

	dwKernelModuleCnt = pstSystemModuleInfo->ModulesCount;
	//保存当前系统所有模块信息（2011.5.14）
	/*
	memset( g_stModuleInfos, 0, sizeof(MODULE_INFO)*g_dwModuleCnt );
	g_dwModuleCnt = dwKernelModuleCnt;
	
	
	for( dwIndex = 0; dwIndex < dwKernelModuleCnt; dwIndex++ )
	{
		g_stModuleInfos[dwIndex].dwModuleBase = (DWORD)pstSystemModuleInfo->Modules[dwIndex].ImageBaseAddress;
		g_stModuleInfos[dwIndex].dwModuleSize =  pstSystemModuleInfo->Modules[dwIndex].ImageSize;
	}
	*/
	for( dwIndex = 0; dwIndex < dwKernelModuleCnt; dwIndex++ )
	{
		//KdPrint("模块路径:%s\n", (char*)(pstSystemModuleInfo->Modules[dwIndex].Name) );
		if( 0 == _strnicmp( (char*)((DWORD)(pstSystemModuleInfo->Modules[dwIndex].Name) + (DWORD)(pstSystemModuleInfo->Modules[dwIndex].NameOffset)), lpKernelModuleName, strlen(lpKernelModuleName) ) )
		{
			strcpy( lpModulePath, "\\??\\c:\\Windows\\System32\\" );
			strcat( lpModulePath, (char*)((DWORD)(pstSystemModuleInfo->Modules[dwIndex].Name) + (DWORD)(pstSystemModuleInfo->Modules[dwIndex].NameOffset)) );
			//找到指定模块，保存其基地址、大小
			*lpModuleBase = (DWORD)pstSystemModuleInfo->Modules[dwIndex].ImageBaseAddress;
			*lpModuleSize = pstSystemModuleInfo->Modules[dwIndex].ImageSize;

			KdPrint(("模块路径:%s,基地址：%x，大小：%d\n", *lpModulePath, *lpModuleBase, lpModuleSize ));
	
			ExFreePoolWithTag( lpBuffer, 0x206B6444 );

			return TRUE;
		}
	}
	


	ExFreePoolWithTag( lpBuffer, 0x206B6444 );
	
	return FALSE;

}

PVOID GetFuncAddrFromModuleExportTable( PVOID pModuleBase, PANSI_STRING pstFuncName, PVOID HookFuncAddr, PDWORD pFuncBaseAddr )
{
	PIMAGE_EXPORT_DIRECTORY pstExportDirectory = NULL;
	DWORD dwSize = 0;
	DWORD dwNameCnt = 0;
	DWORD dwFuncCnt = 0;
	PDWORD pFuncNameArray = NULL;
	PDWORD pFuncAddrArray = NULL;
	PUSHORT pFuncAddrOridinalArray = NULL;
	DWORD dwIndex = 0;
	BOOLEAN bFound = FALSE;
	DWORD dwFuncIndex = 0;

	PVOID pFuncBase = NULL;

	pstExportDirectory = RtlImageDirectoryEntryToData( pModuleBase, TRUE, IMAGE_DIRECTORY_ENTRY_EXPORT, &dwSize );
	//特征码扫描导入函数时，不能直接使用上面的导出函数
	//pstExportDirectory = (PIMAGE_EXPORT_DIRECTORY)GetExportTableEntryAddr( pModuleBase );
	if( pstExportDirectory == NULL )
		return NULL;
		
	pFuncNameArray = (PDWORD)( (DWORD)pModuleBase + pstExportDirectory->AddressOfNames );
	pFuncAddrOridinalArray = (PUSHORT)( (DWORD)pModuleBase + pstExportDirectory->AddressOfNameOrdinals );
	pFuncAddrArray = (PDWORD)( (DWORD)pModuleBase + pstExportDirectory->AddressOfFunctions );
	dwNameCnt = pstExportDirectory->NumberOfNames;
	
	if( dwNameCnt < 1 )//如果导出表中函数数目为0，直接返回NULL
		return NULL;
	//遍历导出表，查找指定名函数地址；360利用的是2分查找法。我这里直接顺序遍历
	for( dwIndex = 0; dwIndex < dwNameCnt; dwIndex++ )
	{
		if( 0 == _stricmp( (char*)(pstFuncName->Buffer), (char*)((DWORD)pModuleBase+pFuncNameArray[dwIndex]) ) )
		{
			bFound = TRUE;
			break;
		}
	
	}
	
	if( !bFound )//遍历完未找到，直接返回失败
		return NULL;
	dwFuncIndex = pFuncAddrOridinalArray[dwIndex];
	if( dwFuncIndex >= pstExportDirectory->NumberOfFunctions )//如果函数地址索引大于函数地址个数，直接返回NULL
		return NULL;
	
	//保存函数基址的地址
	*pFuncBaseAddr = (DWORD)pFuncAddrArray + dwFuncIndex*4;
	pFuncBase = (PVOID)((DWORD)pModuleBase + *(PDWORD)(*pFuncBaseAddr));


	//如果存在Hook函数地址，则Hook该函数
	if( HookFuncAddr != NULL )
	{
		WPOFF();
		InterlockedExchange( (PVOID)(*pFuncBaseAddr), (DWORD)HookFuncAddr-(DWORD)pModuleBase );
		WPON();
	}

	return pFuncBase;

}

BOOLEAN RestoreHook( PVOID pHookAddress, PVOID OriCodeBuffer, DWORD dwLen )
{
	if( MmIsAddressValid( pHookAddress ) )
	{
		WPOFF();
		memcpy( pHookAddress, OriCodeBuffer, dwLen );
		WPON();
		
		return TRUE;
	}
	return FALSE;
}

void HideDriverModuleList( PDRIVER_OBJECT pDriverObject )
{

	PLDR_DATA_TABLE_ENTRY pDriverLdr = (PLDR_DATA_TABLE_ENTRY)(pDriverObject->DriverSection);
	
	((PLDR_DATA_TABLE_ENTRY)(pDriverLdr->InLoadOrderLinks.Flink))->InLoadOrderLinks.Blink = pDriverLdr->InLoadOrderLinks.Blink;
	((PLDR_DATA_TABLE_ENTRY)(pDriverLdr->InLoadOrderLinks.Blink))->InLoadOrderLinks.Flink = pDriverLdr->InLoadOrderLinks.Flink;

	pDriverLdr->InLoadOrderLinks.Flink = (PLIST_ENTRY)pDriverLdr;
	pDriverLdr->InLoadOrderLinks.Blink = (PLIST_ENTRY)pDriverLdr;
	

	//抹去路径信息
}

void HideDriverPe( PDRIVER_OBJECT pDriverObject )
{

	
	DWORD dwLdrDataTableEntry = 0;
	DWORD dwSize = 0;
	
	PIMAGE_DOS_HEADER pDosHeader = NULL;
	PIMAGE_NT_HEADERS pNtHeaders = NULL;
	if( MmIsAddressValid((PVOID)pDriverObject) )
		pDosHeader = (PIMAGE_DOS_HEADER)(pDriverObject->DriverStart);
	if( MmIsAddressValid((PVOID)pDosHeader) )
		pNtHeaders = (PIMAGE_NT_HEADERS)( (ULONG)pDosHeader + pDosHeader->e_lfanew );
	
	dwSize = (DWORD)pNtHeaders - (DWORD)pDosHeader + sizeof(IMAGE_NT_HEADERS);
	memset( pDosHeader, 0, dwSize );

/*
  if( MmIsAddressValid((PVOID)pDosHeader) )
		*(PUSHORT)pDosHeader = 0;
	if( MmIsAddressValid((PVOID)pNtHeaders) )
		*(PULONG)pNtHeaders = 0;
		*/
		
	//抹掉PE结构信息
	
	

	

	//抹掉_ldr_data_table_entry结构信息
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x14)) )
	{
		dwLdrDataTableEntry = *(PULONG)((ULONG)pDriverObject+0x14);
		
		if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x24)) )
			*(PUSHORT)(dwLdrDataTableEntry + 0x24) = 0;
		if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x26)) )
			*(PUSHORT)(dwLdrDataTableEntry + 0x26) = 0;
		if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x28)) )
			*(PDWORD)(dwLdrDataTableEntry + 0x28) = 0;
	}
	
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x18)) )
		*(PDWORD)(dwLdrDataTableEntry + 0x18) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x1c)) )
		*(PDWORD)(dwLdrDataTableEntry + 0x1C) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x20)) )
		*(PUSHORT)(dwLdrDataTableEntry + 0x20) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x24)) )
		*(PUSHORT)(dwLdrDataTableEntry + 0x24) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x26)) )
		*(PUSHORT)(dwLdrDataTableEntry + 0x26) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x28)) )
		*(PDWORD)(dwLdrDataTableEntry + 0x28) = 0;

	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x2c)) )
		*(PUSHORT)(dwLdrDataTableEntry + 0x2C) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x30)) )
		*(PUSHORT)(dwLdrDataTableEntry + 0x30) = 0;
	if( MmIsAddressValid((PVOID)(dwLdrDataTableEntry + 0x34)) )
		*(PDWORD)(dwLdrDataTableEntry + 0x34) = 0;
		
	/*
		ntdll!_DRIVER_OBJECT
   +0x000 Type             : 4
   +0x002 Size             : 168
   +0x004 DeviceObject     : (null) 
   +0x008 Flags            : 2
   +0x00c DriverStart      : 0xf7ea1000 
   +0x010 DriverSize       : 0x8f00
   +0x014 DriverSection    : 0x815584f0 
   +0x018 DriverExtension  : 0x81547790 _DRIVER_EXTENSION
   +0x01c DriverName       : _UNICODE_STRING "\Driver\pipecom"
   +0x024 HardwareDatabase : 0x806727e0 _UNICODE_STRING "\REGISTRY\MACHINE\HARDWARE\DESCRIPTION\SYSTEM"
   +0x028 FastIoDispatch   : (null) 
   +0x02c DriverInit       : 0xf7ea91be     long  snow!GsDriverEntry+0
   +0x030 DriverStartIo    : (null) 
   +0x034 DriverUnload     : (null) 
   +0x038 MajorFunction    : [28] 0x804f455a     long  nt!IopInvalidDeviceReque
   */
		//抹掉DriverObject结构的中的信息
	if( MmIsAddressValid((PVOID)pDriverObject) ) 
		*(PUSHORT)pDriverObject = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+2)) ) 
		*(PUSHORT)((ULONG)pDriverObject+2) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+8)) ) 
		*(PUSHORT)((ULONG)pDriverObject+8) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x0c)) ) 
		*(PUSHORT)((ULONG)pDriverObject+0x0c) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x10)) )//
		*(PULONG)((ULONG)pDriverObject+0x10) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x14)) )
		*(PULONG)((ULONG)pDriverObject+0x14) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x18)) )
		*(PULONG)((ULONG)pDriverObject+0x18) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x1c)) )
		*(PULONG)((ULONG)pDriverObject+0x1c) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+0x20)) )
		*(PULONG)((ULONG)pDriverObject+0x20) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+28)) )
		*(PUSHORT)((ULONG)pDriverObject+28) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+30)) )
		*(PUSHORT)((ULONG)pDriverObject+30) = 0;
	if( MmIsAddressValid((PVOID)((ULONG)pDriverObject+32)) )
		*(PULONG)((ULONG)pDriverObject+32) = 0;

			
}

//获取load_image回调数组地址
PVOID GetLoadImageNotifyArrayBase()
{
		PVOID pPsRemoveLoadImageNotify = NULL;
		UNICODE_STRING stPsRemoveLoadImageNotify = {0};
		PVOID pPsLoadImageNotifyArray = NULL;
		RtlInitUnicodeString( &stPsRemoveLoadImageNotify, L"PsRemoveLoadImageNotifyRoutine" );
		pPsRemoveLoadImageNotify = MmGetSystemRoutineAddress( &stPsRemoveLoadImageNotify );
		if( pPsRemoveLoadImageNotify != NULL )
		{
			UCHAR *pFn=(UCHAR*)pPsRemoveLoadImageNotify;
			ULONG result=0;
			BOOLEAN bFound = FALSE;
			ULONG uCurrent_Build = 0;//系统编号
			PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );
			if( uCurrent_Build >= 7600 )
			{
				pFn=(UCHAR*)pPsRemoveLoadImageNotify;
				do 
				{
					//if( MmIsAddressValid(pFn) && MmIsAddressValid((pFn+1)) && MmIsAddressValid((pFn+9)) && MmIsAddressValid((pFn+12)) ) 
				//	{
						if( (*pFn == 0x33) && (*(pFn+1) == 0x0db) && (*(pFn+9)==0x0ff) && (*(pFn+12)==0x0e8) )
						{
							result=*(DWORD*)(pFn+5);
							if(MmIsAddressValid((PVOID)result))
							{
								bFound = TRUE;
								break;
							}
							else
							{
								bFound =  FALSE;
								result = 0;
								break;
							}
						
						}
				//	}
					pFn++ ;
				} while(pFn<(UCHAR*)pPsRemoveLoadImageNotify+100);
				
			}
			else
			{
				do 
				{
				//	if( MmIsAddressValid(pFn) && MmIsAddressValid((pFn+6)) ) 
				//	{
						if( (*pFn == 0x0bf) && (*(pFn+6)==0xE8) )
						{
							result=*(DWORD*)(pFn+1);
							if(MmIsAddressValid((PVOID)result))
							{
								bFound = TRUE;
								break;
							}
							else
							{
								bFound =  FALSE;
								result = 0;
								break;
							}
							
						}
				//	}
					pFn++ ;
				} while(pFn<(UCHAR*)pPsRemoveLoadImageNotify+0x20);
				
			}
			if( bFound )
				pPsLoadImageNotifyArray = (PVOID)result;
		}
		return pPsLoadImageNotifyArray;
}

PVOID GetLoadImageNotifyAddr( PVOID pPsLoadImageNotifyArray, PVOID pNotifyAddr )
{
			if( MmIsAddressValid(pPsLoadImageNotifyArray) && (pNotifyAddr != NULL) )
			{
				DWORD dwImageLoadAddrBase = 0;
				DWORD dwImageLoadAddr = 0;
				
				DWORD dwIndex = 0;
				BOOLEAN bInside = FALSE;
				DWORD dwFuncAddr = 0;
				for( dwIndex = 0; dwIndex < 8; dwIndex++ )
				{
					if( MmIsAddressValid( (PVOID)((PDWORD)pPsLoadImageNotifyArray+dwIndex) ) )
					{
						dwFuncAddr = *((PDWORD)pPsLoadImageNotifyArray+dwIndex);
						
						dwImageLoadAddrBase = (DWORD)((PDWORD)pPsLoadImageNotifyArray + dwIndex);
						dwImageLoadAddr = dwFuncAddr;
						
						dwFuncAddr &= ~7;
						dwFuncAddr += 4;
						if( MmIsAddressValid((PVOID)dwFuncAddr) )
						{
							dwFuncAddr = *(PDWORD)dwFuncAddr;
							if( (dwFuncAddr != 0) && (dwFuncAddr == (DWORD)pNotifyAddr) )
							{
								bInside = TRUE;
								break;
							}
						}
					}
				}
				if( bInside )
				{
					return (PVOID)dwImageLoadAddrBase;
					//DWORD dwTemp = 0;
					//g_pImageLoadAddrBase[g_dwImageLoadCnt] = dwImageLoadAddrBase;
					//g_pImageLoadAddr[g_dwImageLoadCnt++] = dwImageLoadAddr;
					//RestoreHook( (PVOID)dwImageLoadAddrBase, &dwTemp, sizeof(DWORD) );
					//((NTSTATUS (*)(PLOAD_IMAGE_NOTIFY_ROUTINE))g_pPsRemoveLoadImageNotify)( (PLOAD_IMAGE_NOTIFY_ROUTINE)dwFuncAddr );
				}
			}
			return NULL;
}

BOOLEAN IsLoadImageNotifyAddrExist( PVOID pNotifyAddr )
{
	PVOID pLoadImageNotifyBase = NULL;
	PVOID pPsLoadImageNotifyArray = GetLoadImageNotifyArrayBase();
	if( pPsLoadImageNotifyArray != NULL )
	{
				//获取模块映射回调数组基地址后，遍历获取指定回调所在地址
				pLoadImageNotifyBase = GetLoadImageNotifyAddr( pPsLoadImageNotifyArray, (PVOID)pNotifyAddr );
				if( pLoadImageNotifyBase != NULL )
					return TRUE;
	}
	return FALSE;
}

PVOID GetCmpCallbackListHeader()
{
				ULONG uCurrent_Build = 0;//系统编号
				PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );
				if( uCurrent_Build >= 7600 )
				{
					//for win7
					DWORD dwIndex = 0;
					UNICODE_STRING stUnRegCallback = {0};
					PVOID pUnRegCallbackAddr = NULL;

					RtlInitUnicodeString( &stUnRegCallback, L"CmUnRegisterCallback" );
					pUnRegCallbackAddr = MmGetSystemRoutineAddress( &stUnRegCallback );
					KdPrint(( "FuncAddr1:%x\n", pUnRegCallbackAddr ));

				
					for( dwIndex = 0; dwIndex < 200; dwIndex++ )
					{
				
						if( ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex))==0x56) && ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+1))==0x8d) && 
							((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+2))==0x4d) && ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+3))==0xd4) &&
							((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+4))==0xbf) )
						{
							DWORD dwCallbackListHeader = *(PDWORD)((DWORD)pUnRegCallbackAddr+dwIndex+5);
							if( MmIsAddressValid((PVOID)dwCallbackListHeader) )
							{
								BOOLEAN bInside = FALSE;
								DWORD dwCallbackList = *(PDWORD)dwCallbackListHeader;
								KdPrint(( "List:%x", dwCallbackList ));
								return (PVOID)dwCallbackList;

							}//end if
						}
					}//end for

				}
				else
				{
					DWORD dwIndex = 0;
					UNICODE_STRING stRegCallback = {0};
					PVOID pRegCallbackAddr = NULL;

					RtlInitUnicodeString( &stRegCallback, L"CmRegisterCallback" );
					pRegCallbackAddr = MmGetSystemRoutineAddress( &stRegCallback );

					KdPrint(( "FuncAddr2:%x\n", pRegCallbackAddr ));

					for( dwIndex = 0; dwIndex < 200; dwIndex++ )
					{
				
						if( ((*(PBYTE)((DWORD)pRegCallbackAddr+dwIndex))==0x89) && ((*(PBYTE)((DWORD)pRegCallbackAddr+dwIndex+1))==0x7d) )
						{
							DWORD dwCallbackArray = *(PDWORD)((DWORD)pRegCallbackAddr+dwIndex-4);
							if( MmIsAddressValid((PVOID)dwCallbackArray) )
							{
								return (PVOID)dwCallbackArray;
							}//end if
						}
					}//end for
				}//end else(for xp)
				return NULL;
}


BOOLEAN IsCmpRegisterCallbackAddrExist( PVOID pCallbackAddr )
{
				ULONG uCurrent_Build = 0;//系统编号
				PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );
				if( uCurrent_Build >= 7600 )
				{
					//for win7
					DWORD dwIndex = 0;
					UNICODE_STRING stUnRegCallback = {0};
					PVOID pUnRegCallbackAddr = NULL;

					RtlInitUnicodeString( &stUnRegCallback, L"CmUnRegisterCallback" );
					pUnRegCallbackAddr = MmGetSystemRoutineAddress( &stUnRegCallback );
					KdPrint(( "FuncAddr1:%x\n", pUnRegCallbackAddr ));

				
					for( dwIndex = 0; dwIndex < 200; dwIndex++ )
					{
				
						if( ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex))==0x56) && ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+1))==0x8d) && 
							((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+2))==0x4d) && ((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+3))==0xd4) &&
							((*(PBYTE)((DWORD)pUnRegCallbackAddr+dwIndex+4))==0xbf) )
						{
							DWORD dwCallbackListHeader = *(PDWORD)((DWORD)pUnRegCallbackAddr+dwIndex+5);
							if( MmIsAddressValid((PVOID)dwCallbackListHeader) )
							{
								BOOLEAN bInside = FALSE;
								DWORD dwCallbackList = *(PDWORD)dwCallbackListHeader;
								KdPrint(( "List:%x", dwCallbackList ));
								do
								{
									if( MmIsAddressValid((PVOID)dwCallbackList) && MmIsAddressValid( (PVOID)(dwCallbackList+0x1c)) )
									{
										DWORD dwFuncAddr = *(PDWORD)(dwCallbackList+0x1c);
										if( (dwFuncAddr != 0 ) && ( dwFuncAddr == (DWORD)pCallbackAddr) );
										{
											//win7该结构为双向链表
											//保存被摘除的链表节点
											PLIST_ENTRY pTempList = (PLIST_ENTRY)dwCallbackList;
											//g_pDeletedCmpLists[g_dwDeletedCmpListsCnt++] = pTempList;
										
											//((PLIST_ENTRY)(pTempList->Blink))->Flink = pTempList->Flink;
										  //((PLIST_ENTRY)(pTempList->Flink))->Blink = pTempList->Blink;
											
											KdPrint(( "find" ));
											bInside = TRUE;
											break;
										
										}


									}
									dwCallbackList = *(PDWORD)dwCallbackList;
								}while ( dwCallbackList != dwCallbackListHeader );

								if( bInside )
								{
									return TRUE;
								}//end if
								else
									return FALSE;

							}//end if
						}
					}//end for

				}
				else
				{
					DWORD dwIndex = 0;
					UNICODE_STRING stRegCallback = {0};
					PVOID pRegCallbackAddr = NULL;

					RtlInitUnicodeString( &stRegCallback, L"CmRegisterCallback" );
					pRegCallbackAddr = MmGetSystemRoutineAddress( &stRegCallback );

					KdPrint(( "FuncAddr2:%x\n", pRegCallbackAddr ));

				

					for( dwIndex = 0; dwIndex < 200; dwIndex++ )
					{
				
						if( ((*(PBYTE)((DWORD)pRegCallbackAddr+dwIndex))==0x89) && ((*(PBYTE)((DWORD)pRegCallbackAddr+dwIndex+1))==0x7d) )
						{
							DWORD dwCallbackArray = *(PDWORD)((DWORD)pRegCallbackAddr+dwIndex-4);
							if( MmIsAddressValid((PVOID)dwCallbackArray) )
							{
								DWORD dwIndex = 0;
								BOOLEAN bInside = FALSE;
								DWORD dwFuncAddr = 0;
								for( dwIndex = 0; dwIndex < 8; dwIndex++ )
								{
									if( MmIsAddressValid( (PVOID)((PDWORD)dwCallbackArray+dwIndex) ) )
									{
										dwFuncAddr = *((PDWORD)dwCallbackArray+dwIndex);
										dwFuncAddr &= ~7;
										dwFuncAddr += 4;
										if( MmIsAddressValid((PVOID)dwFuncAddr) )
										{
											dwFuncAddr = *(PDWORD)dwFuncAddr;
											if( (dwFuncAddr != 0) && ( dwFuncAddr == (DWORD)pCallbackAddr) )
											{
												bInside = TRUE;
												break;
											}
										}
									}
								}//end for
								if( bInside )
								{
										return TRUE;
										//DWORD dwTemp = 0;
										//g_pCmpCallbackAddrBase[g_dwCmpCallbackCnt] = (DWORD)((PDWORD)dwCallbackArray+dwIndex);
										//g_pCmpCallbackAddr[g_dwCmpCallbackCnt++] = *((PDWORD)dwCallbackArray+dwIndex);
										//KdPrint(("摘除定时器:%d",g_dwCmpCallbackCnt));
										
										//RestoreHook( (PVOID)((PDWORD)dwCallbackArray+dwIndex), &dwTemp, sizeof(DWORD) );
								
								
								}//end if
								else
									return FALSE;

							}//end if
						}
					}//end for
				}//end else(for xp)
				return FALSE;
}

PVOID GetIoTimerQueueHeader()
{
			PVOID pIoInitializeTimer = NULL;
			DWORD pIopTimerQueueHead = 0;
			UNICODE_STRING stFuncName = {0};

			RtlInitUnicodeString( &stFuncName, L"IoInitializeTimer" );
			pIoInitializeTimer = MmGetSystemRoutineAddress( &stFuncName );
			if( pIoInitializeTimer != NULL )
			{
				DWORD dwIndex = 0;
				DWORD dwTimerCnt = 0;
				for( dwIndex = 0; dwIndex < 0x100; dwIndex++ )
				{

					if( ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex))==0xb9) && ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex+5))==0xe8) && ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex+0x0a))==0x33) )
					{
						BOOLEAN bFind = FALSE;
						pIopTimerQueueHead = *(PDWORD)((DWORD)pIoInitializeTimer+dwIndex+1);
						if( MmIsAddressValid((PVOID)pIopTimerQueueHead) )
						{
							return (PVOID)pIopTimerQueueHead;
						}
					}
				}
			}
			
			return NULL;
}

BOOLEAN IsIoTimerAddrExist( PVOID pIoTimer )
{
			PVOID pIoInitializeTimer = NULL;
			DWORD pIopTimerQueueHead = 0;
			UNICODE_STRING stFuncName = {0};
			BOOLEAN bRestored = FALSE;

			RtlInitUnicodeString( &stFuncName, L"IoInitializeTimer" );
			pIoInitializeTimer = MmGetSystemRoutineAddress( &stFuncName );
			if( pIoInitializeTimer != NULL )
			{
				DWORD dwIndex = 0;
				DWORD dwTimerCnt = 0;
				for( dwIndex = 0; dwIndex < 0x100; dwIndex++ )
				{

					if( ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex))==0xb9) && ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex+5))==0xe8) && ((*(PBYTE)((DWORD)pIoInitializeTimer+dwIndex+0x0a))==0x33) )
					{
						BOOLEAN bFind = FALSE;
						pIopTimerQueueHead = *(PDWORD)((DWORD)pIoInitializeTimer+dwIndex+1);
						if( MmIsAddressValid((PVOID)pIopTimerQueueHead) )
						{
							DWORD dwBegin = pIopTimerQueueHead;
							
							dwBegin = pIopTimerQueueHead;
							do
							{
								if( MmIsAddressValid((PVOID)(dwBegin+8)) )
								{
									DWORD dwFuncBase = *(PDWORD)(dwBegin+8);
									if( (dwFuncBase != 0) && (dwFuncBase == (DWORD)pIoTimer) )
									{
										//2011.08.28，保存被摘除的timer节点
										//PLIST_ENTRY pTimerList = (PLIST_ENTRY)dwBegin;
										//g_pDeletedTimerLists[g_dwDeletedTimerListsCnt++] = (PLIST_ENTRY)dwBegin;
										
										//((PLIST_ENTRY)(pTimerList->Blink))->Flink = pTimerList->Flink;
										//((PLIST_ENTRY)(pTimerList->Flink))->Blink = pTimerList->Blink;
										//dwTimerCnt++;
										//KdPrint(("摘除定时器:%d,%x",dwTimerCnt,dwFuncBase ));
										//	break;
										return TRUE;
									
									}
								}
								if( MmIsAddressValid((PVOID)(dwBegin+4)) )
									dwBegin = *(PDWORD)(dwBegin+4);
								else
									break;

							}while (dwBegin != pIopTimerQueueHead);
                            
							/*
							//摘除GamesGuard驱动的定时器
							dwBegin = *(PDWORD)(pIopTimerQueueHead);
							do
							{
									if( MmIsAddressValid((PVOID)(dwBegin+8)) )
									{
										DWORD dwFuncBase = *(PDWORD)(dwBegin+8);
										if( (dwFuncBase != 0) && (!AddressIsInSafeModule(dwFuncBase) || AddressInDangerModule(dwFuncBase) ) )
										{
											//2011.08.28，保存被摘除的timer节点
											PLIST_ENTRY pTimerList = (PLIST_ENTRY)dwBegin;
											g_pDeletedTimerLists[g_dwDeletedTimerListsCnt++] = (PLIST_ENTRY)dwBegin;
											
											((PLIST_ENTRY)(pTimerList->Blink))->Flink = pTimerList->Flink;
											((PLIST_ENTRY)(pTimerList->Flink))->Blink = pTimerList->Blink;
											bRestored = TRUE;
											dwTimerCnt++;
											KdPrint(("摘除定时器:%d,%x",dwTimerCnt,dwFuncBase ));
											
											break;
										}
									}
									if( MmIsAddressValid((PVOID)(dwBegin)) )
										dwBegin = *(PDWORD)(dwBegin);
									else
										break;

							}while (dwBegin != pIopTimerQueueHead);
							*/

						
							break;
						}
					}
				}
			}
			return FALSE;
}


BOOLEAN IsSystemThreadExist( PVOID pStartRoutine )
{
		DWORD dwIndex = 1;
		DWORD dwStartRoutineOffset = GetPlantformDependentInfo( THREAD_START_ROUTINE_OFFSET );
		DWORD dwProcessThreadListHeaderOffset = GetPlantformDependentInfo( PROCESS_THREADLISTHEAD_OFFSET );
		DWORD dwThreadListEntryOffset = GetPlantformDependentInfo( THREAD_LISTENTRY_OFFSET );
		PLIST_ENTRY pPreListEntry = NULL;
		PLIST_ENTRY pCurListEntry = NULL;
		PEPROCESS pSystemEProcess = GetSystemEProcess();
		pPreListEntry = (PLIST_ENTRY)((DWORD)pSystemEProcess + dwProcessThreadListHeaderOffset);
		pCurListEntry = pPreListEntry->Flink;
		
		//test
		do
		{
			PVOID pStartRoutineBaseAddr = (PVOID)((DWORD)(pCurListEntry) - dwStartRoutineOffset);
			if( MmIsAddressValid(pStartRoutineBaseAddr) )
			{
				DWORD dwStartRoutineAddr = *(PDWORD)(pStartRoutineBaseAddr);
				//if( ((dwGamesGuardBase<dwStartRoutineAddr) && (dwStartRoutineAddr<(dwGamesGuardBase+dwGamesGuardSize))) || (!AddressIsInSafeModule(dwStartRoutineAddr)) )
				if( (dwStartRoutineAddr != 0) && (dwStartRoutineAddr == (DWORD)pStartRoutine) )
				{
					return TRUE;
					//说明是游戏创建的内核线程
					//PETHREAD pEThread = (PETHREAD)((DWORD)(pCurListEntry) - dwThreadListEntryOffset);
					//g_pSuspendedThreads[g_dwSuspendedThreadsCnt++] = pEThread;
					//if( g_pPsSuspendThreadAddr != NULL )
					//	((NTSTATUS (NTAPI*)(PETHREAD,PULONG))g_pPsSuspendThreadAddr)( pEThread, NULL );
					//KdPrint(("线程%d:%x", dwIndex, pEThread));
				}
			}
			pCurListEntry = pCurListEntry->Flink;
		}while( pCurListEntry != pPreListEntry );
		return FALSE;
}


PVOID GetShutdownPacketBaseAddr()
{
	PVOID pIoRegisterShutdownNotification = NULL;
	PSHUTDOWN_PACKET pShutdownPacket = NULL;
	UNICODE_STRING stFuncName = {0};
	BOOLEAN bFind = FALSE;
	ULONG uCurrent_Build = 0;//系统编号
	PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );
	
	RtlInitUnicodeString( &stFuncName, L"IoRegisterShutdownNotification" );
	pIoRegisterShutdownNotification = MmGetSystemRoutineAddress( &stFuncName );
	if( pIoRegisterShutdownNotification != NULL )
	{
		if( uCurrent_Build >= 7600 )
		{
			//搜寻特征码
			DWORD index = 0;
			for( index = 0; index < 70; index++ )
			{
				if( ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index)) == 0xe8) && ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+5)) == 0xbf) &&
						((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+10)) == 0xe8) )
				{
					//找到特征码
					DWORD pShutdownPacketAddr = *(PDWORD)((DWORD)pIoRegisterShutdownNotification+index+5+1);
					if( MmIsAddressValid((PVOID)pShutdownPacketAddr) )
					{
						return (PVOID)pShutdownPacketAddr;
					}
				}
			}
		}
		else
		{
			
			//搜寻特征码
			DWORD index = 0;
			for( index = 0; index < 70; index++ )
			{
				if( ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index)) == 0x8b) && ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+1)) == 0xd7) &&
						((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+2)) == 0xb9) )
				{
					//找到特征码
					DWORD pShutdownPacketAddr = *(PDWORD)((DWORD)pIoRegisterShutdownNotification+index+2+1);
					if( MmIsAddressValid((PVOID)pShutdownPacketAddr) )
					{
						return (PVOID)pShutdownPacketAddr;
					}
				}
			}
		}
	}
	return NULL;
}

BOOLEAN IsShowdownExist( PDEVICE_OBJECT pDeviceObject )
{
	PVOID pIoRegisterShutdownNotification = NULL;
	PSHUTDOWN_PACKET pShutdownPacket = NULL;
	UNICODE_STRING stFuncName = {0};
	BOOLEAN bFind = FALSE;
	ULONG uCurrent_Build = 0;//系统编号
	PsGetVersion( NULL, NULL, &uCurrent_Build, NULL );
	RtlInitUnicodeString( &stFuncName, L"IoRegisterShutdownNotification" );
	pIoRegisterShutdownNotification = MmGetSystemRoutineAddress( &stFuncName );
	if( pIoRegisterShutdownNotification != NULL )
	{
		if( uCurrent_Build >= 7600 )
		{
			//搜寻特征码
			DWORD index = 0;
			for( index = 0; index < 70; index++ )
			{
				if( ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index)) == 0xe8) && ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+5)) == 0xbf) &&
						((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+10)) == 0xe8) )
				{
					//找到特征码
					DWORD pShutdownPacketAddr = *(PDWORD)((DWORD)pIoRegisterShutdownNotification+index+5+1);
					if( MmIsAddressValid((PVOID)pShutdownPacketAddr) )
					{
						pShutdownPacket = (PSHUTDOWN_PACKET)(*((PDWORD)pShutdownPacketAddr));
						bFind = TRUE;
						break;
					}
				}
			}
		}
		else
		{
			//搜寻特征码
			DWORD index = 0;
			for( index = 0; index < 70; index++ )
			{
				if( ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index)) == 0x8b) && ((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+1)) == 0xd7) &&
						((*(PBYTE)((DWORD)pIoRegisterShutdownNotification+index+2)) == 0xb9) )
				{
					//找到特征码
					DWORD pShutdownPacketAddr = *(PDWORD)((DWORD)pIoRegisterShutdownNotification+index+2+1);
					if( MmIsAddressValid((PVOID)pShutdownPacketAddr) )
					{
						pShutdownPacket = (PSHUTDOWN_PACKET)(*((PDWORD)pShutdownPacketAddr));
						bFind = TRUE;
						break;
					}
				}
			}
		}
	}
	
	if( bFind )
	{
		//找到关机回写链表
		PSHUTDOWN_PACKET tmpShutdownPacket = pShutdownPacket;
		if( MmIsAddressValid(tmpShutdownPacket) )
		{
			do
			{
				if( tmpShutdownPacket->DeviceObject == pDeviceObject )
					return TRUE;
				tmpShutdownPacket = (PSHUTDOWN_PACKET)(tmpShutdownPacket->ListEntry.Flink);
			}while( tmpShutdownPacket != pShutdownPacket);
		}
	}
	
	return FALSE;
	
}

PVOID GetSysBuffer( PCWSTR pSysPath, PDWORD pdwSize )
{
	UNICODE_STRING Filename = {0};
	OBJECT_ATTRIBUTES obj = {0};
	HANDLE filehand = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK  IoStatus = {0};
	LARGE_INTEGER byteoffset = {0};
	PVOID pBuffer = NULL;
	RtlInitUnicodeString(&Filename,pSysPath);
	InitializeObjectAttributes(&obj, &Filename, OBJ_CASE_INSENSITIVE, NULL, NULL ); 
	//判断文件是否存在
	status = ZwCreateFile( &filehand, GENERIC_READ, &obj, &IoStatus, NULL, FILE_ATTRIBUTE_NORMAL,
													FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0 );
	if( NT_SUCCESS(status))
	{
		//获取文件大小
		FILE_STANDARD_INFORMATION stFileStandardInfo = {0};
		status = ZwQueryInformationFile( filehand, &IoStatus, &stFileStandardInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
		if( NT_SUCCESS(status) )
		{
			*pdwSize = (DWORD)(stFileStandardInfo.EndOfFile.QuadPart);
			pBuffer = ExAllocatePool(NonPagedPool,*pdwSize);
			if( pBuffer != NULL )
			{
				//读取文件内容
				byteoffset.QuadPart = 0;
				status = ZwReadFile( filehand, NULL, NULL, NULL, &IoStatus, pBuffer, *pdwSize, &byteoffset, NULL );
				if( !NT_SUCCESS(status) )
				{
					ExFreePool(pBuffer);
					pBuffer = NULL;
					*pdwSize = 0;
				}
			}
		}
		ZwClose(filehand);
		filehand = NULL;
	}
	
	return pBuffer;
}

/*
映射文件，并获取PE文件版本信息
*/
NTSTATUS MapPe( PCWSTR path, PWORD majorVer, PWORD minorVer )
{
		HANDLE hFile = NULL;
		HANDLE hSection = NULL;
		IO_STATUS_BLOCK stIoStatusBlock = {0};
		NTSTATUS Status = STATUS_SUCCESS;
		UNICODE_STRING stPath = {0};

		PVOID pNewModuleBase = NULL;
		DWORD dwNewSize = 0;
		
		OBJECT_ATTRIBUTES stObjectAttributes = {0};
		RtlInitUnicodeString( &stPath, path);
		InitializeObjectAttributes( &stObjectAttributes, &stPath, OBJ_CASE_INSENSITIVE, NULL, NULL );

		

		Status = ZwOpenFile( &hFile,  FILE_EXECUTE | SYNCHRONIZE, &stObjectAttributes, &stIoStatusBlock, FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT );
		if( !NT_SUCCESS(Status) )
		{
			return 0xC0000001;
		}
		stObjectAttributes.ObjectName = NULL;
		Status = ZwCreateSection( &hSection, SECTION_ALL_ACCESS, &stObjectAttributes, NULL, PAGE_EXECUTE, SEC_IMAGE, hFile );
		if( !NT_SUCCESS(Status) )
		{
			ZwClose( hFile );
			return 0xC0000001;

		}
		Status = ZwMapViewOfSection(hSection, NtCurrentProcess(), &pNewModuleBase, 0, 1000, 0, &dwNewSize, (SECTION_INHERIT)1, MEM_TOP_DOWN, PAGE_READWRITE ); 
		if( !NT_SUCCESS(Status) )
		{
			ZwClose( hFile );
			ZwClose( hSection );
			return 0xC0000001;

		}

		ZwClose( hFile );

    //解析pe文件
    Status = GetSoftVersion(pNewModuleBase, majorVer, minorVer);
    
		
		ZwUnmapViewOfSection( NtCurrentProcess(), pNewModuleBase );
		ZwClose( hSection );
		
		return Status;
}

/*
获取PE文件版本信息
*/
NTSTATUS GetSoftVersion( PVOID pFileData, PWORD majorVer, PWORD minorVer )
{
	PIMAGE_DOS_HEADER pDosH = (PIMAGE_DOS_HEADER)pFileData;
	PIMAGE_NT_HEADERS pNtH = (PIMAGE_NT_HEADERS)( (ULONG)pFileData + pDosH->e_lfanew );
	PIMAGE_RESOURCE_DIRECTORY pResource = (PIMAGE_RESOURCE_DIRECTORY)( (ULONG)pFileData + pNtH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress );
  PIMAGE_RESOURCE_DATA_ENTRY pDataEntry = GetVersionInfoEntry(pResource);
  if( MmIsAddressValid(pDataEntry) )
  {
  	DWORD size = pDataEntry->Size;
  	VS_VERSIONINFO* pVS = (VS_VERSIONINFO*)((DWORD)pFileData+pDataEntry->OffsetToData);
  	PBYTE pVt = (PBYTE)&pVS->szKey[wcslen(pVS->szKey) + 1];
    VS_FIXEDFILEINFO* pValue = (VS_FIXEDFILEINFO*)ROUND_POS(pVt, pVS, 4);
    if ( pVS->wValueLength )
    {
    	int struver = pValue->dwStrucVersion >> 16;
    	int struver2 = pValue->dwStrucVersion & 0xFFFF;
    	
    	int filev1 = pValue->dwFileVersionMS >> 16;
      int filev2 = pValue->dwFileVersionMS & 0xFFFF; 
      int filev3 = pValue->dwFileVersionLS >> 16;
      int filev4 = pValue->dwFileVersionLS & 0xFFFF;
      
      *majorVer = pValue->dwProductVersionMS >> 16;
      *minorVer = pValue->dwProductVersionMS & 0xFFFF;
      //int prov3 = pValue->dwProductVersionLS >> 16;
      //int prov4 = pValue->dwProductVersionLS & 0xFFFF;


		}
  	return STATUS_SUCCESS; 
  }
	
	return STATUS_UNSUCCESSFUL;
}

// 获取版本号信息入口点
PIMAGE_RESOURCE_DATA_ENTRY GetVersionInfoEntry( PIMAGE_RESOURCE_DIRECTORY pRootRec )
{
		WORD i = 0;
    WORD nCount = pRootRec->NumberOfIdEntries + pRootRec->NumberOfNamedEntries;
    for ( i = 0; i < nCount; ++i )
    {
        PIMAGE_RESOURCE_DIRECTORY_ENTRY pFirstEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)( (PDWORD)pRootRec + 
            sizeof(IMAGE_RESOURCE_DIRECTORY) / sizeof(DWORD) ) + i;
        
        if ( pFirstEntry->Id != (WORD)16 )
            continue;

        // 进入目录
        if ( pFirstEntry->DataIsDirectory == 0x01 )
        {
        		WORD nIndex = 0;
            PIMAGE_RESOURCE_DIRECTORY pFirstDir = (PIMAGE_RESOURCE_DIRECTORY) ( (PBYTE)pRootRec + pFirstEntry->OffsetToDirectory );
            WORD nDirCount = pFirstDir->NumberOfNamedEntries + pFirstDir->NumberOfIdEntries;

            // 第二层目录(资源代码页)
            for ( nIndex = 0; nIndex < nDirCount; ++nIndex )
            {
                PIMAGE_RESOURCE_DIRECTORY_ENTRY pSecondEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)( (PDWORD)pFirstDir + 
                    sizeof(IMAGE_RESOURCE_DIRECTORY) / sizeof(DWORD) ) + nIndex;

                // 取第三层目录(资源数据入口)
                if ( pSecondEntry->DataIsDirectory == 1 )
                {
                    PIMAGE_RESOURCE_DIRECTORY pThirdDir = (PIMAGE_RESOURCE_DIRECTORY)( (PBYTE)pRootRec + pSecondEntry->OffsetToDirectory );
                    if ( pThirdDir->NumberOfIdEntries + pThirdDir->NumberOfNamedEntries == 1 )
                    {
                        // 有一个Entry
                        PIMAGE_RESOURCE_DIRECTORY_ENTRY pThirdEntry = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)( (PDWORD)pThirdDir + 
                            sizeof(IMAGE_RESOURCE_DIRECTORY) / sizeof(DWORD) );    
                        if ( pThirdEntry->DataIsDirectory == 0 )
                        {
                            PIMAGE_RESOURCE_DATA_ENTRY pData = ( PIMAGE_RESOURCE_DATA_ENTRY )( (PBYTE)pRootRec + pThirdEntry->OffsetToDirectory );
                            if ( pData )
                            {
                                // 找到真实数据入口点
                                return pData;
                            }
                        }
                    }
                }
            }
        }
    }

    return NULL;
}



NTSTATUS WriteFileRes(PCWSTR filename,PVOID buf,ULONG length, WORD major, WORD minor )
{
	UNICODE_STRING Filename = {0};
	OBJECT_ATTRIBUTES obj = {0};
	HANDLE filehand = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	IO_STATUS_BLOCK  IoStatus = {0};
	WORD majVer = 0;
	WORD minVer = 0;
	BOOLEAN bRefresh = TRUE;
	
	status = MapPe( filename, &majVer, &minVer );
	if( NT_SUCCESS(status) )
	{
		if( (majVer > major) || ( (majVer == major) && (minor <= minVer) ) )
			bRefresh = FALSE;
	}
	if( bRefresh )
	{
		RtlInitUnicodeString(&Filename,filename);
		InitializeObjectAttributes(&obj, &Filename, OBJ_CASE_INSENSITIVE, NULL, NULL ); 
		//判断文件版本信息
		
		ZwDeleteFile( &obj );
		status = ZwCreateFile(&filehand,
			FILE_APPEND_DATA,
			&obj,
			&IoStatus,
			0, 
			FILE_ATTRIBUTE_NORMAL,
			FILE_SHARE_WRITE,
			FILE_OPEN_IF,
			FILE_SYNCHRONOUS_IO_NONALERT,
			NULL,     
			0 );
		if (NT_SUCCESS(status))
		{
			status= ZwWriteFile(filehand,
				NULL,
				NULL,
				NULL,
				&IoStatus,
				buf,
				length,
				NULL,
				NULL );
			if (NT_SUCCESS(status))
			{
				ZwClose(filehand);
				return STATUS_SUCCESS;
			}else
			{
				KdPrint(("ZwWriteFile Faild:%.8x",status));
				return	STATUS_UNSUCCESSFUL;
			}
		}else
		{
			KdPrint(("ZwCreateFile Faild:%.8x",status));
			return STATUS_UNSUCCESSFUL;
		}
	}
	return STATUS_SUCCESS;
}

//创建注册表项
NTSTATUS WriteRegister( PCWSTR keyPath, PCWSTR displayName, DWORD dwErrorControl, PCWSTR imagePath, DWORD dwStart, DWORD dwType )
{
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING stKeyPath = {0};
	OBJECT_ATTRIBUTES stObj = {0};
	HANDLE hKey = NULL;
	
	//显示名
	UNICODE_STRING stDisplayName = {0};
	//ErrorControl
	UNICODE_STRING stErrorControl = {0};
	//ImagePath
	UNICODE_STRING stImagePath = {0};
	//Start
	UNICODE_STRING stStart = {0};
	//Type
	UNICODE_STRING stType = {0};
	
	
	RtlInitUnicodeString( &stKeyPath, keyPath);
	InitializeObjectAttributes(&stObj, &stKeyPath, OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenKey( &hKey, GENERIC_ALL, &stObj );
	if( !NT_SUCCESS(status) )
	{
		//注册表项不存在，创建
		status = ZwCreateKey( &hKey, GENERIC_ALL, &stObj, 0, NULL, 0, NULL );
		if( !NT_SUCCESS(status) )
			return status;
	}
	//设置注册表值
	//设置显示名
	RtlInitUnicodeString( &stDisplayName, L"DisplayName" );
	status = ZwSetValueKey( hKey, &stDisplayName, 0, REG_SZ, (PVOID)displayName, wcslen(displayName)*2+2 );
	
	RtlInitUnicodeString( &stErrorControl, L"ErrorControl" );
	status = ZwSetValueKey( hKey, &stErrorControl, 0, REG_DWORD, &dwErrorControl, sizeof(dwErrorControl) );
	
	RtlInitUnicodeString( &stImagePath, L"ImagePath" );
	status = ZwSetValueKey( hKey, &stImagePath, 0, REG_EXPAND_SZ, (PVOID)imagePath, wcslen(imagePath)*2+2 );
	
	RtlInitUnicodeString( &stStart, L"Start" );
	status = ZwSetValueKey( hKey, &stStart, 0, REG_DWORD, &dwStart, sizeof(dwStart) );
	
	RtlInitUnicodeString( &stType, L"Type" );
	status = ZwSetValueKey( hKey, &stType, 0, REG_DWORD, &dwType, sizeof(dwStart) );
	ZwClose( hKey );
	
	return status;
}

//获取指定注册，指定键的值
VOID GetSysFile( PUNICODE_STRING pRegisterPath, PUNICODE_STRING pKey, PWSTR *pKeyValue )
{
	//读取注册表中的驱动文件路径
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES stObj = {0};
	HANDLE hKey = NULL;
	
	InitializeObjectAttributes( &stObj, pRegisterPath, OBJ_CASE_INSENSITIVE, NULL, NULL );
	status = ZwOpenKey( &hKey, GENERIC_READ, &stObj );
	
	if( NT_SUCCESS(status) )
	{
		//读取ImagePath键值
		//KEY_VALUE_PARTIAL_INFORMATION stValue = {0};
		PVOID pValue = NULL;
		DWORD dwSize = 0;
		
		status = ZwQueryValueKey( hKey, pKey, KeyValuePartialInformation, NULL, 0, &dwSize );
		if( !NT_SUCCESS(status) && (dwSize != 0) )
		{
			pValue = ExAllocatePool(NonPagedPool,dwSize);
			
			if( pValue != NULL )
			{
				memset( pValue, 0, dwSize );
				status = ZwQueryValueKey( hKey, pKey, KeyValuePartialInformation, pValue, dwSize, &dwSize);
				if( NT_SUCCESS(status) )
				{
					DWORD dwLen = 0;
					PKEY_VALUE_PARTIAL_INFORMATION pKeyValuePartailInfo = (PKEY_VALUE_PARTIAL_INFORMATION)pValue;
					dwLen = pKeyValuePartailInfo->DataLength;
					*pKeyValue = (PWSTR)ExAllocatePool( NonPagedPool, dwLen+1 );
					
					if( *pKeyValue != NULL )
					{
						memset( *pKeyValue, 0, dwLen+1 );
						memcpy( *pKeyValue, pKeyValuePartailInfo->Data, dwLen);
					}
					
				}
				ExFreePool(pValue);
				pValue = NULL;
			}
			
		}
		ZwClose(hKey);
	}
	
}

