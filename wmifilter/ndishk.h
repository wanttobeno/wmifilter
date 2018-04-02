//ndis hook
#include <ntifs.h>
#include <ndis.h>
#ifndef _FUN_H
#define _FUN_H

#ifndef	NDIS_API 
#define NDIS_API __stdcall	 
#endif 

NTSTATUS HookNdis();
//遍历NDIS_PROTOCOL_BLOCK结构链表，hook SendHandler、SendPackageHandler函数
NTSTATUS HookNdisProtocolBlockList( PNDIS_PROTOCOL_BLOCK pNdisProtocolBlock );
//根据特征码获取NDIS_PROTOCOL_BLOCK链首地址
PNDIS_PROTOCOL_BLOCK GetGlobalProtocolBlockList( PVOID pFuncAddr );
NTSTATUS HookNdisSendNetBufferLists( PVOID pFuncAddr );

typedef
VOID
(NDIS_API *NDISSEND)(
    PNDIS_STATUS Status,
    NDIS_HANDLE NdisBindingHandle,
    PNDIS_PACKET Packet
);
extern NDISSEND m_pNdisSend;



typedef
VOID 
(NDIS_API *NDISREGISTERPROTOCOL)(
    OUT PNDIS_STATUS Status,
    OUT PNDIS_HANDLE NdisProtocolHandle,
    IN PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
    IN UINT CharacteristicsLength
);
extern NDISREGISTERPROTOCOL m_pNdisRegisterProtocol;

typedef
VOID (NDIS_API *OPENADAPTERCOMPLETE)(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status,
    IN NDIS_STATUS OpenErrorStatus
);
extern OPENADAPTERCOMPLETE m_pOpenAdapterComplete;

typedef
VOID 
(NDIS_API *NDISOPENADAPTER)(
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
extern NDISOPENADAPTER m_pNdisOpenAdapter;
extern NDIS_HANDLE m_TcpipHandle;

typedef
NDIS_STATUS 
(NDIS_API *RECEIVE)(
    IN NDIS_HANDLE NdisBindingContext,
    IN NDIS_HANDLE MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
);
extern RECEIVE m_pNdisReceive;

typedef
NDIS_STATUS 
(NDIS_API *SENDPACKET)(
	IN	NDIS_HANDLE				MacBindingHandle,
	IN	PNDIS_PACKET			Packet
);
extern SENDPACKET m_pSendHandler;

typedef
VOID 
(NDIS_API *WANSENDPACKETS)(
	IN NDIS_HANDLE  NdisBindingHandle,
	IN PPNDIS_PACKET  PacketArray,
	IN UINT  NumberOfPackets
);
extern WANSENDPACKETS m_pWanSendPackets;
extern NDIS_HANDLE m_TcpIpWanHandle;

#endif
