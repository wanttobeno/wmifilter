#include "precomp.h"
#include "funclib.h"
#include "myfun.h"

BOOLEAN bHooked = FALSE;
DWORD dwNdisSendNetBufferLists = 0;
//hook nids部分导出函数
NTSTATUS HookNdis()
{
	NTSTATUS status = STATUS_SUCCESS;
	DWORD dwModuleBase = 0;
	DWORD dwModuleSize = 0;
	char szPath[512] = {0};
	ANSI_STRING stFuncName = {0};

		//xp
		DWORD dwFuncAvAddr = 0;
		PVOID pFuncAddr = NULL;
		PNDIS_PROTOCOL_BLOCK pNdisProtocolBlock = NULL;
	
		BOOLEAN bFind = GetKernelModuleInfo( "tcpip.sys", &dwModuleBase, &dwModuleSize, szPath );
		if( !bFind )
		{
			return STATUS_UNSUCCESSFUL;
		}
		//获取tcpip.sys模块导出函数IPDelayedNdisReEnumerateBindings地址
		RtlInitAnsiString( &stFuncName, "IPDelayedNdisReEnumerateBindings" );
		pFuncAddr = GetFuncAddrFromModuleExportTable( (PVOID)dwModuleBase, &stFuncName, NULL, &dwFuncAvAddr );
		if( pFuncAddr == NULL )
			return STATUS_UNSUCCESSFUL;
	
		//从IPDelayedNdisReEnumerateBindings函数搜索NDIS_PROTOCOL_BLOCK链首地址
		pNdisProtocolBlock = GetGlobalProtocolBlockList( pFuncAddr );
		if( pNdisProtocolBlock == NULL )
			return STATUS_UNSUCCESSFUL;
	
		status = HookNdisProtocolBlockList( pNdisProtocolBlock );
		return status;
	
}

//根据特征码获取NDIS_PROTOCOL_BLOCK链首地址
PNDIS_PROTOCOL_BLOCK GetGlobalProtocolBlockList( PVOID pFuncAddr )
{
	DWORD index = 0;
	DWORD dwAddr = 0;
	for( index = 0; index < 50; index++ )
	{
		if( *(PSHORT)((DWORD)pFuncAddr+index) == 0x35ff )
			break;
	}
	
	if( index < 50 )
	{
		//找到特征码
		dwAddr = *(PDWORD)((DWORD)pFuncAddr+index+2);
		return (PNDIS_PROTOCOL_BLOCK)(*(PDWORD)dwAddr);
	}
	return NULL;
}

//遍历NDIS_PROTOCOL_BLOCK结构链表，hook SendHandler、SendPackageHandler函数
NTSTATUS HookNdisProtocolBlockList( PNDIS_PROTOCOL_BLOCK pNdisProtocolBlock )
{
	NTSTATUS Status = STATUS_SUCCESS;
	PNDIS_PROTOCOL_BLOCK pTmpNdisProtocolBlock = pNdisProtocolBlock;
	while( pTmpNdisProtocolBlock != NULL )
	{
		//循环遍历链表
		PNDIS_OPEN_BLOCK pNdisOpenBlock = pTmpNdisProtocolBlock->OpenQueue;
		if( pNdisOpenBlock != NULL )
		{
			if(pNdisOpenBlock->SendHandler != NULL )
			{
				m_pSendHandler = pNdisOpenBlock->SendHandler;
				pNdisOpenBlock->SendHandler = MY_SendPacket;
			}
			
			if( pNdisOpenBlock->SendPacketsHandler != NULL )
			{
				m_pWanSendPackets = pNdisOpenBlock->SendPacketsHandler;
				pNdisOpenBlock->SendPacketsHandler = MY_WanSendPackets;
			}
		}
		pTmpNdisProtocolBlock = pTmpNdisProtocolBlock->NextProtocol;
	}
	return Status;
}

/*
//inline hook NdisSendNetBufferLists
void _declspec(naked) _xxNdisSendNetBufferLists( NDIS_HANDLE NdisBindingHandle, PNET_BUFFER_LIST NetBufferLists, NDIS_PORT_NUMBER  PortNumber,ULONG SendFlags )
{
	_asm
	{
		push [esp+8]
		call MY_NdisSendNetBufferLists
		test eax,eax
		jnz _ok
		xor eax,eax
		ret 10h
		_ok:
		mov edi,edi
		push ebp
		mov ebp,esp
		jmp [dwNdisSendNetBufferLists]
		
	}
}



NTSTATUS HookNdisSendNetBufferLists( PVOID pFuncAddr )
{
	char jmpByte[] = {0xe9,0x00,0x00,0x00,0x00};
	DWORD distance = 0;
	dwNdisSendNetBufferLists = (DWORD)pFuncAddr + 5;
	distance = (DWORD)MY_NdisSendNetBufferLists - dwNdisSendNetBufferLists;
	
	memcpy( (char*)(jmpByte+1), &distance, 4 );
	RestoreHook( pFuncAddr, jmpByte, 5 );
	
	return STATUS_SUCCESS;
}*/

