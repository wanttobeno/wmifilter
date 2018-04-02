#include "precomp.h"
#include <windef.h>
#include "miniporthk.h"
#include "funclib.h"
#include "analysispacket.h"

pNdisMIndicateReceiveNetBufferListsInternal_vista_later	g_oriNdisMIndicateReceiveNetBufferLists;
pSendNetBufferLists		g_oriNdisSendBufferLists;
ULONG	*g_addr_for_unhook_NdisMIndicateReceiveNetBufferListsInternal;
ULONG	*g_addr_for_unhook_NdisMSendNetBufferList;

ULONG	g_u_recv_offset_in_miniport_vista_later=0x19c;
ULONG	g_u_send_offset_in_miniport_vista	=	0xa00;
ULONG	g_u_send_offset_in_miniport_win7	=	0xe04;

//
//hook miniport driver
NTSTATUS HookMiniPort( PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath )
{
	 NDIS_STRING Name = {0};
   DWORD g_u_mini_driver_block_head = 0;
	 NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
	 PDRIVER_OBJECT	DriverObject	=	NULL;//ExAllocatePoolWithTag(NonPagedPool, sizeof(DRIVER_OBJECT);
	
	 NDIS_HANDLE NdisWrapperHandle=NULL;
	 NDIS_HANDLE DriverHandle	=NULL;
   myNDIS51_MINIPORT_CHARACTERISTICS_vista_later MChars = {0};;
   
	 
	 DriverObject	=	pDriverObject;//InitDriverObject();so much things we need to offer
	 Status = NDIS_STATUS_SUCCESS;
	 NdisMInitializeWrapper(&NdisWrapperHandle, DriverObject, pRegistryPath, NULL);
	
	 NdisZeroMemory(&MChars, sizeof(myNDIS51_MINIPORT_CHARACTERISTICS_vista_later) );
	
	 MChars.Ndis50Chars.MajorNdisVersion = 5;
	 if (GetWindowsVersion()!=Windows_2K)
	{
		MChars.Ndis50Chars.MinorNdisVersion = 1;
	}
	
	/*
	MChars.InitializeHandler = NULL;
	MChars.QueryInformationHandler = NULL;
	MChars.SetInformationHandler = NULL;
	MChars.ResetHandler = NULL;
	MChars.TransferDataHandler = NULL;
	MChars.HaltHandler = NULL;

	MChars.CancelSendPacketsHandler = NULL;
	MChars.PnPEventNotifyHandler = NULL;
    MChars.AdapterShutdownHandler = NULL;
	MChars.SendHandler = NULL;    // MPSend;
	MChars.SendPacketsHandler = NULL;
	*/
	MChars.AdapterShutdownHandler	=	MPAdapterShutdown;
	Status = NdisIMRegisterLayeredMiniport(NdisWrapperHandle,(PNDIS_MINIPORT_CHARACTERISTICS)&MChars,sizeof(MChars),&DriverHandle);
	if (Status!=NDIS_STATUS_SUCCESS)
	{
		KdPrint(("[miniport_hook] NdisIMRegisterLayeredMiniport fail, error : 0x%X\n", Status));
		return NDIS_STATUS_SUCCESS;	//随便返回啦
	}
//	__asm int 3
	KdPrint(("[miniport_hook] NdisIMRegisterLayeredMiniport ori_driver_block_list_head :%p, NdisWrapperHandle:0x%X, DriverHandle : 0x%X\n", g_u_mini_driver_block_head, NdisWrapperHandle, DriverHandle));
	DriverHandle	=	(NDIS_HANDLE)((ULONG)DriverHandle+4);
	g_u_mini_driver_block_head	=	*(ULONG*)DriverHandle;	//取出
	KdPrint(("[miniport_hook] NdisIMRegisterLayeredMiniport ori_driver_block_list_head :%p\n", g_u_mini_driver_block_head));
//	__asm int 3
	NdisIMDeregisterLayeredMiniport(DriverHandle);	//取消注册
	NdisTerminateWrapper(NdisWrapperHandle, NULL);
	if (g_u_mini_driver_block_head==0)
	{
		KdPrint(("[miniport_hook] ungeiliable ...fuck!!\r\n"));
	}
	miniport_hook_vista_later(g_u_mini_driver_block_head);
	return 1;
}


ULONG  GetWindowsVersion()
{
	ULONG	dwMajorVersion;
	ULONG	dwMinorVersion;
	PsGetVersion(&dwMajorVersion, &dwMinorVersion, NULL, NULL);
	if (dwMajorVersion == 5 && dwMinorVersion == 0) 
	{
		
		DbgPrint("Window 2K \n");
		return Windows_2K;
		
	} else if (dwMajorVersion == 5 && dwMinorVersion == 1) {
		DbgPrint("Window XP \n");
		return Windows_XP;
	} else if (dwMajorVersion == 5 && dwMinorVersion == 2) {
        DbgPrint("Window 2003 \n");
		return Windows_2k3;	
	} else if (dwMajorVersion == 6 && dwMinorVersion == 0) 
	{
		DbgPrint("Window Vista \n");
		return Windows_Vista;
	}
	else if (dwMajorVersion == 6 && dwMinorVersion == 1) {
		DbgPrint("Window 7 \n");
		return Windows_7;
	}
	
	return 0;
}

VOID
MPAdapterShutdown(
    IN NDIS_HANDLE                MiniportAdapterContext
    )
/*++

Routine Description:

    This handler is called to notify us of an impending system shutdown.

Arguments:

    MiniportAdapterContext    - pointer to ADAPT structure

Return Value:

    None
--*/
{
    UNREFERENCED_PARAMETER(MiniportAdapterContext);
    
    return;
}


void miniport_hook_vista_later(ULONG	u_miniport_block_list_head)
{
	my_NDIS_M_DRIVER_BLOCK_vista_later	*p_m_driver_block	=	(my_NDIS_M_DRIVER_BLOCK_vista_later*)u_miniport_block_list_head;
	//有杀错没放过
	while(p_m_driver_block)
	{
		if (p_m_driver_block->MajorNdisVersion	==6 )	//为6的都HOOK
		{
			
			//更完整的应该再遍历miniport 链，(一个驱动可以产生多个miniport)
			//就TMDHOOK一个地方吧
			if (check_target_miniport_vista_later((ULONG)(p_m_driver_block->MiniportQueue)))
			{
				DbgPrint(("target find\r\n"));
				hook_recv_vista_later((ULONG)(p_m_driver_block->MiniportQueue));	
				hook_send_vista_later((ULONG)(p_m_driver_block->MiniportQueue));
				break ;
			}
		}
		p_m_driver_block	=	p_m_driver_block->NextDriver;

	}
}

BOOLEAN	check_target_miniport_vista_later(ULONG	uminiport)
{
	NDIS_STATUS	status;
	UNICODE_STRING	PCIDriverNameString;
	PDEVICE_OBJECT	pci_DriverObject;
	PNDIS_MINIPORT_BLOCK	pmini_block;//
	DEVICE_OBJECT	*PhysicalDeviceObject;
	
	pmini_block=	(PNDIS_MINIPORT_BLOCK)uminiport;
	if (GetWindowsVersion()==Windows_7)
	{
		PhysicalDeviceObject	=	(DEVICE_OBJECT*)(*(ULONG*)((ULONG)pmini_block+0xe5c));
	}
	else
	{
		PhysicalDeviceObject	=	(DEVICE_OBJECT*)(*(ULONG*)((ULONG)pmini_block+0xa58));
	}
	
	RtlInitUnicodeString(&PCIDriverNameString, L"\\Driver\\pci");
	
	status = ObReferenceObjectByName(&PCIDriverNameString, OBJ_CASE_INSENSITIVE, 0, 0, *IoDriverObjectType,KernelMode, 0, &pci_DriverObject);
	if (status!=NDIS_STATUS_SUCCESS)
	{
		//DbgPrint(("[miniport ] ObReferenceObjectByName fail code %x\r\n",status));
		return FALSE;
	}
	if( (PDEVICE_OBJECT)(PhysicalDeviceObject->DriverObject)	==	pci_DriverObject)
	{
		//DbgPrint(("[miniport] get the target miniport block\r\n"));
		return TRUE;
	}
	
	return FALSE;
	
}

VOID	hook_recv_vista_later(ULONG	mini_block)
{
	
	PNDIS_MINIPORT_BLOCK	p_mini_block	=	(PNDIS_MINIPORT_BLOCK)mini_block;
	g_addr_for_unhook_NdisMIndicateReceiveNetBufferListsInternal	=	(ULONG*)(mini_block+g_u_recv_offset_in_miniport_vista_later);
	
	//保存
	g_oriNdisMIndicateReceiveNetBufferLists	=	(pNdisMIndicateReceiveNetBufferListsInternal_vista_later)*g_addr_for_unhook_NdisMIndicateReceiveNetBufferListsInternal;
	
	//替换
	*g_addr_for_unhook_NdisMIndicateReceiveNetBufferListsInternal	=	(ULONG)myNdisMIndicateReceiveNetBufferListsInternal_vista_later;
	return ;
}

VOID	hook_send_vista_later(ULONG	mini_block)
{
	PLONG	ptmp =  NULL;
	if (GetWindowsVersion()==Windows_Vista)
	{
		ptmp	=	(PLONG)(mini_block+g_u_send_offset_in_miniport_vista);
	}
	if (GetWindowsVersion()==Windows_7)
	{
		ptmp	=	(PLONG)(mini_block+g_u_send_offset_in_miniport_win7);
	}

	ptmp	=	(PLONG)*ptmp;	//_NDIS_M_DRIVER_BLOCK
	ptmp	=	(PLONG)((ULONG)ptmp	+0x60);
	g_addr_for_unhook_NdisMSendNetBufferList	=	ptmp;
	g_oriNdisSendBufferLists	=	(pSendNetBufferLists)*g_addr_for_unhook_NdisMSendNetBufferList;
	*g_addr_for_unhook_NdisMSendNetBufferList	=	(ULONG)myMPSendNetBufferLists;
}


void myNdisMIndicateReceiveNetBufferListsInternal_vista_later(
												 NDIS_HANDLE MiniportAdapterHandle,
												 PNET_BUFFER_LIST NetBufferLists,
												 ULONG PortNumber,
												 ULONG NumberOfNetBufferLists,
												 ULONG ReceiveFlags
)
{
	ULONG             NumNbls=0;
	PNET_BUFFER_LIST  Nbl;
	PNET_BUFFER_LIST  NextNbl = NULL;
	PNET_BUFFER NetBuffer;
	ULONG	uNetBuffer_length=0;

	//loop over the nbls
	for ( Nbl = NetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
    {
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{
		//要想高效的话，可以找出最大的netbuffer,申请一次，后面的都用它就行了，现在先不管。
		 //redirect_recv_netbuffer_vista_later(NetBuffer);
		//	uNetBuffer_length	=	NET_BUFFER_DATA_LENGTH(NetBuffer);
        }
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);
	}
//	KdPrint(("[miniport_hook] myNdisMIndicateReceiveNetBufferListsInternal_vista_later invoked %d,%d\n",NumNbls, NumberOfNetBufferLists));
	g_oriNdisMIndicateReceiveNetBufferLists(MiniportAdapterHandle, NetBufferLists, PortNumber, NumberOfNetBufferLists, ReceiveFlags);
	return ;
}

VOID
myMPSendNetBufferLists(
					   NDIS_HANDLE             MiniportAdapterContext,
					   PNET_BUFFER_LIST        NetBufferLists,
					   PVOID        PortNumber,
					   ULONG                   SendFlags)
{
	ULONG             NumNbls=0;
	PNET_BUFFER_LIST  Nbl;
	PNET_BUFFER_LIST  NextNbl = NULL;
	PNET_BUFFER NetBuffer;
	ULONG	uNetBuffer_length=0;
	BOOLEAN bSafe = TRUE;
	
	//loop over the nbls
	for ( Nbl = NetBufferLists; Nbl!= NULL; Nbl = NextNbl, ++NumNbls)
  {
		//loop over nbs
		for ( NetBuffer = NET_BUFFER_LIST_FIRST_NB(Nbl); NetBuffer != NULL; NetBuffer = NET_BUFFER_NEXT_NB(NetBuffer))
		{
			//要想高效的话，可以找出最大的netbuffer,申请一次，后面的都用它就行了，现在先不管。
			if( AnalysisNetBuffer( NetBuffer, FALSE ) != 0 )
			{
				return;
			}
			//redirect_send_netbuffer_vista_later(NetBuffer, inet_addr(REDIRECT_FORM_IP), inet_addr(REDIRECT_TO_IP));
			//uNetBuffer_length	=	NET_BUFFER_DATA_LENGTH(NetBuffer);
    }
    
		NextNbl = NET_BUFFER_LIST_NEXT_NBL(Nbl);	
  }
//	KdPrint(("[miniport_hook] myMPSendNetBufferLists invoked %d\n", NumNbls));
	g_oriNdisSendBufferLists(MiniportAdapterContext, NetBufferLists, PortNumber, SendFlags);
}