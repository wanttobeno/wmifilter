#ifndef	_MYFUN_H
#define _MYFUN_H

#pragma once
#include <ntifs.h>
#include <ndis.h>

#define PASS 0
#define HOOK_SEND	1
#define HOOK_SEND_PACKETS 2

#define NDIS_API __stdcall

#define UNICODE_STRING_CONST(x)	{sizeof(L##x)-2, sizeof(L##x), L##x}

typedef struct _NDIS_PROTOCOL_BLOCK
{
	PNDIS_OPEN_BLOCK				OpenQueue;				// queue of opens for this protocol
	REFERENCE						Ref;					// contains spinlock for OpenQueue
	UINT							Length;					// of this NDIS_PROTOCOL_BLOCK struct
	NDIS50_PROTOCOL_CHARACTERISTICS	ProtocolCharacteristics;// handler addresses

	struct _NDIS_PROTOCOL_BLOCK *	NextProtocol;			// Link to next
	ULONG							MaxPatternSize;
#if defined(NDIS_WRAPPER)
	//
	// Protocol filters
	//
	struct _NDIS_PROTOCOL_FILTER *	ProtocolFilter[NdisMediumMax+1];
	WORK_QUEUE_ITEM					WorkItem;				// Used during NdisRegisterProtocol to
															// notify protocols of existing drivers.
	KMUTEX							Mutex;					// For serialization of Bind/Unbind requests
	PKEVENT							DeregEvent;				// Used by NdisDeregisterProtocol
#endif
}NDIS_PROTOCOL_BLOCK,*PNDIS_PROTOCOL_BLOCK;


//NDIS_STATUS MY_NdisSendNetBufferLists( IN PVOID NetBufferLists );
VOID NDIS_API
MY_NdisSend(
    PNDIS_STATUS Status,
    NDIS_HANDLE NdisBindingHandle,
    PNDIS_PACKET Packet
);
VOID NDIS_API
MY_NdisRegisterProtocol(
    OUT PNDIS_STATUS Status,
    OUT PNDIS_HANDLE NdisProtocolHandle,
    IN PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
    IN UINT CharacteristicsLength
);
VOID NDIS_API
MY_OpenAdapterComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status,
    IN NDIS_STATUS OpenErrorStatus
);
NDIS_STATUS NDIS_API
MY_Receive(
    IN NDIS_HANDLE NdisBindingContext,
    IN NDIS_HANDLE MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
);
VOID NDIS_API
MY_NdisOpenAdapter(
	OUT PNDIS_STATUS  Status,
	OUT PNDIS_STATUS  OpenErrorStatus,
	OUT PNDIS_HANDLE  NdisBindingHandle,
	OUT PUINT  SelectedMediumIndex,
	IN PNDIS_MEDIUM  MediumArray,
	IN UINT  MediumArraySize,
	IN NDIS_HANDLE  NdisProtocolHandle,
	IN NDIS_HANDLE  ProtocolBindingContext,
	IN PNDIS_STRING  AdapterName,
	IN UINT  OpenOptions,
	IN PSTRING  AddressingInformation  OPTIONAL
);
VOID 
MY_HookSend(
	IN NDIS_HANDLE	ProtocolBlock, 
	IN PVOID		HookFunction,
	OUT PVOID*		SendHandler,
	IN unsigned char			HookType
);
NDIS_STATUS NDIS_API
MY_SendPacket(
	IN	NDIS_HANDLE				MacBindingHandle,
	IN	PNDIS_PACKET			Packet
);

VOID NDIS_API
MY_WanSendPackets(
	IN NDIS_HANDLE  NdisBindingHandle,
	IN PPNDIS_PACKET  PacketArray,
	IN UINT  NumberOfPackets
);
int CheckSend(
	IN PNDIS_PACKET packet
);
int CheckPacket(
	IN PNDIS_PACKET packet,
	IN BOOLEAN IsSend
);
int CheckRecv(
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
);



#endif