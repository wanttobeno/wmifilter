#ifndef _miniporthk_
#define _miniporthk_

#include <ndis.h>
//////////////////////////////////////////////////////////////////////////

#define Windows_2K	2000
#define Windows_XP	2001
#define Windows_2k3	2003
#define Windows_Vista	2004
#define Windows_7	2005
//////////////////////////////////////////////////////////////////////////
//º¯ÊýÉùÃ÷
NTSTATUS HookMiniPort( PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath );
ULONG GetWindowsVersion();
//VOID	MPAdapterShutdown( IN NDIS_HANDLE MiniportAdapterContext );
//void miniport_hook_vista_later(ULONG	u_miniport_block_list_head);
//BOOLEAN	check_target_miniport_vista_later(ULONG	uminiport);



BOOLEAN	check_target_miniport_vista_later(ULONG	uminiport);
void	unhook();

void	miniport_hook_vista_later(ULONG	u_miniport_block_list_head);
VOID
MPAdapterShutdown(
				  IN NDIS_HANDLE                MiniportAdapterContext
				  );

//////////////////////////////////////////////////////////////////////////

typedef VOID (*pNdisMIndicateReceiveNetBufferListsInternal_vista_later)(
											  NDIS_HANDLE MiniportAdapterHandle,
											  PNET_BUFFER_LIST NetBufferLists,
											  ULONG PortNumber,
											  ULONG NumberOfNetBufferLists,
											  ULONG ReceiveFlags
);

typedef VOID (*pSendNetBufferLists)(
					   NDIS_HANDLE             MiniportAdapterContext,
					   PNET_BUFFER_LIST        NetBufferLists,
					   PVOID        PortNumber,
						  ULONG                   SendFlags);
//////////////////////////////////////////////////////////////////////////
void myNdisMIndicateReceiveNetBufferListsInternal_vista_later(
															  NDIS_HANDLE MiniportAdapterHandle,
															  PNET_BUFFER_LIST NetBufferLists,
															  ULONG PortNumber,
															  ULONG NumberOfNetBufferLists,
															  ULONG ReceiveFlags
);

VOID
myMPSendNetBufferLists(
						  NDIS_HANDLE             MiniportAdapterContext,
						  PNET_BUFFER_LIST        NetBufferLists,
						  PVOID        PortNumber,
						  ULONG                   SendFlags);

VOID	hook_recv_vista_later(ULONG	mini_block);
VOID	hook_send_vista_later(ULONG	mini_block);

typedef struct _my_NDIS_M_DRIVER_BLOCK_vista_later
{
	PVOID	Header;		//_NDIS_OBJECT_HEADER
	struct _my_NDIS_M_DRIVER_BLOCK_vista_later * NextDriver;
	NDIS_MINIPORT_BLOCK	*	MiniportQueue;
	UCHAR	MajorNdisVersion;
	UCHAR	MinorNdisVersion;
}my_NDIS_M_DRIVER_BLOCK_vista_later;


typedef struct _myNDIS51_MINIPORT_CHARACTERISTICS_vista_later
{
    NDIS50_MINIPORT_CHARACTERISTICS Ndis50Chars;
	
    //
    // Extensions for NDIS 5.1
    //
	//     W_CANCEL_SEND_PACKETS_HANDLER   CancelSendPacketsHandler;
	//     W_PNP_EVENT_NOTIFY_HANDLER      PnPEventNotifyHandler;
	//     W_MINIPORT_SHUTDOWN_HANDLER     AdapterShutdownHandler;
    PVOID   CancelSendPacketsHandler;
    PVOID      PnPEventNotifyHandler;
    PVOID     AdapterShutdownHandler;
    PVOID                           Reserved1;
    PVOID                           Reserved2;
    PVOID                           Reserved3;
    PVOID                           Reserved4;
} myNDIS51_MINIPORT_CHARACTERISTICS_vista_later;





#endif