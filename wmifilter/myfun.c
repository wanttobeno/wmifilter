#include "precomp.h"
#include "myfun.h"
#include "ndishk.h"
#include "memory.h"
#include "windef.h"
#include "stdio.h"
#include "analysispacket.h"
#pragma comment(lib,"ntoskrnl.lib")
#pragma comment(lib,"wdm.lib")
#pragma comment(lib,"libcntpr.lib")


NDISSEND m_pNdisSend = NULL;
NDISREGISTERPROTOCOL m_pNdisRegisterProtocol = NULL;
OPENADAPTERCOMPLETE m_pOpenAdapterComplete = NULL;
NDISOPENADAPTER m_pNdisOpenAdapter = NULL;
NDIS_HANDLE m_TcpipHandle;
RECEIVE m_pNdisReceive = NULL;
SENDPACKET m_pSendHandler = NULL;
WANSENDPACKETS m_pWanSendPackets = NULL;
NDIS_HANDLE m_TcpIpWanHandle = NULL;

/*
//win7检测网络包
NDIS_STATUS MY_NdisSendNetBufferLists( IN PVOID NetBufferLists )
{
	NTSTATUS status = STATUS_SUCCESS;
	PVOID pNetBufferList = NetBufferLists;
	while( pNetBufferList != NULL )
	{
		PVOID pNetBuffer = NULL;
		for( pNetBuffer = NET_BUFFER_LIST_FIRST_NB(pNetBufferList); pNetBuffer != NULL; pNetBuffer = NET_BUFFER_NEXT_NB(pNetBuffer) )
		{
			if( ((int)AnalysisNetBuffer(pNetBuffer, FALSE)) != 0 )
				return NDIS_STATUS_SUCCESS;
		}
		pNetBufferList = NET_BUFFER_LIST_NEXT_NBL(pNetBufferList);
	}
	return NDIS_STATUS_FAILURE;
}

*/

VOID NDIS_API
MY_NdisSend(
    PNDIS_STATUS Status,
    NDIS_HANDLE NdisBindingHandle,
    PNDIS_PACKET Packet
)
{
    KdPrint(("MY_NdisSend\n"));
    m_pNdisSend(Status, NdisBindingHandle, Packet);
}

VOID NDIS_API
MY_NdisRegisterProtocol(
    OUT PNDIS_STATUS Status,
    OUT PNDIS_HANDLE NdisProtocolHandle,
    IN PNDIS_PROTOCOL_CHARACTERISTICS ProtocolCharacteristics,
    IN UINT CharacteristicsLength
)
{
    BOOLEAN bHookedTcp = FALSE;
    UNICODE_STRING usTcpName = UNICODE_STRING_CONST("TCPIP");

    KdPrint(("MY_NdisRegisterProtocol\n"));

    if(m_pNdisRegisterProtocol == NULL)
        return;

    //
    // 判断是否是TCP/IP协议
    //
    if(usTcpName.Length == ProtocolCharacteristics->Name.Length 
        && memcmp(ProtocolCharacteristics->Name.Buffer, usTcpName.Buffer, usTcpName.Length) == 0)
    {
        bHookedTcp = TRUE;
        m_pOpenAdapterComplete = ProtocolCharacteristics->OpenAdapterCompleteHandler;
        ProtocolCharacteristics->OpenAdapterCompleteHandler = MY_OpenAdapterComplete;
        m_pNdisReceive = ProtocolCharacteristics->ReceiveHandler;
        ProtocolCharacteristics->ReceiveHandler = MY_Receive;
    }

    //
    // 转发给系统函数
    //
    m_pNdisRegisterProtocol(
        Status,
        NdisProtocolHandle,
        ProtocolCharacteristics,
        CharacteristicsLength
        );

    if(bHookedTcp)
    {
        m_TcpipHandle = *NdisProtocolHandle;
        bHookedTcp = TRUE;
    }
}

VOID NDIS_API
MY_OpenAdapterComplete(
    IN NDIS_HANDLE ProtocolBindingContext,
    IN NDIS_STATUS Status,
    IN NDIS_STATUS OpenErrorStatus
)
{
    KdPrint(("MY_OpenAdapterComplete\n"));

    //
    // 调用MY_HookSend对SendHander进行Hook。
    //
	if(Status == NDIS_STATUS_SUCCESS)
        MY_HookSend(m_TcpipHandle, MY_SendPacket, (PVOID*)&m_pSendHandler, HOOK_SEND);

    m_pOpenAdapterComplete(
        ProtocolBindingContext,
        Status,
        OpenErrorStatus
        );
}


NDIS_STATUS NDIS_API
MY_Receive(
    IN NDIS_HANDLE NdisBindingContext,
    IN NDIS_HANDLE MacReceiveContext,
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
)
{

	return 1;
}

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
)
{

	m_pNdisOpenAdapter(
		Status,
		OpenErrorStatus,
		NdisBindingHandle,
		SelectedMediumIndex,
		MediumArray,
		MediumArraySize,
		NdisProtocolHandle,
		ProtocolBindingContext,
		AdapterName,
		OpenOptions,
		AddressingInformation
		);


	if(*Status != STATUS_SUCCESS)
		return;

	if(NdisProtocolHandle == m_TcpipHandle)
		MY_HookSend(m_TcpipHandle, MY_SendPacket, (PVOID*)&m_pSendHandler, HOOK_SEND);
	else if(NdisProtocolHandle == m_TcpIpWanHandle)
		MY_HookSend(m_TcpIpWanHandle, MY_WanSendPackets, (PVOID*)&m_pWanSendPackets, HOOK_SEND_PACKETS);
}

VOID 
MY_HookSend(
	IN NDIS_HANDLE	ProtocolBlock, 
	IN PVOID		HookFunction,
	OUT PVOID*		SendHandler,
	IN unsigned char			HookType
)
{
#if _MSC_VER > 1600
	KdPrint(("MY_HookSend不支持\n"));
#else
	if(ProtocolBlock != NULL)
	{
		PNDIS_PROTOCOL_BLOCK pProtocol = NULL;

		PNDIS_OPEN_BLOCK pOpenBlock = NULL;
		pProtocol = (PNDIS_PROTOCOL_BLOCK)ProtocolBlock;
		pOpenBlock = pProtocol->OpenQueue;

		switch(HookType)
		{
		case HOOK_SEND:
			if(pOpenBlock != NULL && pOpenBlock->SendHandler != NULL)
			{
				*SendHandler = pOpenBlock->SendHandler;
			}
			while(pOpenBlock != NULL)
			{
				pOpenBlock->SendHandler =HookFunction;
				pOpenBlock = pOpenBlock->ProtocolNextOpen;
			}
			break;
		case HOOK_SEND_PACKETS:
			if(pOpenBlock != NULL && pOpenBlock->SendPacketsHandler != NULL)
			{
				*SendHandler = pOpenBlock->SendPacketsHandler;
			}
			while(pOpenBlock != NULL)
			{
				pOpenBlock->SendPacketsHandler =HookFunction;
				pOpenBlock = pOpenBlock->ProtocolNextOpen;
			}
			break;
		}
	}
#endif  // _MSC_VER > 1600
}

NDIS_STATUS NDIS_API
MY_SendPacket(
	IN	NDIS_HANDLE				MacBindingHandle,
	IN	PNDIS_PACKET			Packet
)
{

	//
	// 检查封包的合法性
	//
	if(CheckSend(Packet) != 0)
		return NDIS_STATUS_SUCCESS;//不合法，返回
	
	//
	// 转发给系统函数
	//
	return m_pSendHandler(MacBindingHandle, Packet);
}
VOID NDIS_API
MY_WanSendPackets(
	IN NDIS_HANDLE  NdisBindingHandle,
	IN PPNDIS_PACKET  PacketArray,
	IN UINT  NumberOfPackets
)
{
	UINT i;

	for(i = 0; i < NumberOfPackets; i++)
	{
		if(CheckPacket(PacketArray[i], TRUE) != 0)
			return;
	}

	m_pWanSendPackets(NdisBindingHandle, PacketArray, NumberOfPackets);
}
int CheckSend(
	IN PNDIS_PACKET packet
)
{

	return CheckPacket(packet, TRUE);
}
int CheckPacket(
	IN PNDIS_PACKET packet,
	IN BOOLEAN IsSend
)
{
	return (int)AnalysisPacket( packet, !IsSend);
	
	/*
 	PNDIS_BUFFER  FirstBuffer, Buffer;
	UINT TotalPacketLength;
	unsigned int EthernetFrameType;
	int HeaderLength;
	PIP_HEADER pIpHeader;
	PETHERNET_FRAME pEthernetFrame;
	void* pBiosBuffer;
	PICMP_HEADER pIcmpHeader;
	PTCP_HEADER pTcpHeader;
	PUDP_HEADER pUdpHeader;

	UINT PhysicalBufferCount;
	UINT BufferCount;
	PVOID VirtualAddress;
	int Length = 0;

	dprintf(("CheckSend\n"));

	//
	// 得到第一个NDIS_BUFFER
	//
	TotalPacketLength = 0;
	NdisQueryPacket(packet
		, &PhysicalBufferCount
		, &BufferCount
		, &FirstBuffer
		, &TotalPacketLength
		);

	if(FirstBuffer == NULL)
		return PASS;

	Buffer = FirstBuffer;

	//
	// 解析Ethernet Frame
	//
	NdisQueryBufferSafe(FirstBuffer, &VirtualAddress, &Length, HighPagePriority);
	pEthernetFrame = (PETHERNET_FRAME)VirtualAddress;
	EthernetFrameType = ntohs(pEthernetFrame->FrameType);

	if(EthernetFrameType != ETHERNET_FRAME_TYPE_TCPIP)//不是IP协议，PASS
		return PASS;

	//
	// 解析Ip Header
	//
	if((Length - ETHERNET_FRAME_LENGTH) >= IP_HEADER_LENGTH)
	{
		pIpHeader = (PIP_HEADER)((char*)pEthernetFrame + ETHERNET_FRAME_LENGTH);//跳到IP头
		Length = Length - ETHERNET_FRAME_LENGTH;
	}
	else
	{
		NdisGetNextBuffer(FirstBuffer, &Buffer);

		if(Buffer == NULL)
			return PASS;

		NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);

		if(VirtualAddress == NULL || Length < IP_HEADER_LENGTH)
			return PASS;

		pIpHeader = (PIP_HEADER)VirtualAddress;
	}

	HeaderLength = pIpHeader->HeaderLength * HEADER_LENGTH_MULTIPLE;

	dprintf(("HeaderLength: %u\n", HeaderLength));

	switch(pIpHeader->Protocol)
	{
	case PROTOCOL_TCP:
		//
		// 解析Tcp Header
		//
		if((Length - HeaderLength) < TCP_HEADER_LENGTH)
		{

			NdisGetNextBuffer(Buffer, &Buffer);
			if(Buffer == NULL) return PASS;
			NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);
			if(VirtualAddress != NULL && Length >= TCP_HEADER_LENGTH)
			{
				pTcpHeader = (PTCP_HEADER)(VirtualAddress);
			}
			else
			{
				return PASS;
			}
		}
		else
		{
			pTcpHeader = (PTCP_HEADER)((unsigned long)pIpHeader + HeaderLength);
		}


		pBiosBuffer = NULL;
		if(Buffer != NULL)
		{
			NdisGetNextBuffer(Buffer, &Buffer);
			if(Buffer != NULL)
			{
				NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);
				if(VirtualAddress != NULL && Length >= NETBIOS_MIN_PACKET_SIZE)
					pBiosBuffer = (void*)VirtualAddress;
			} 
		}
		//
		// 调用CheckTcp对封包的合法性进行审查
		//
		return CheckTcp(pIpHeader, pTcpHeader, IsSend, TotalPacketLength, pBiosBuffer);

	case PROTOCOL_UDP:
		//
		// 解析UDP Header
		//
		if((Length - HeaderLength) < UDP_HEADER_LENGTH)
		{
			//
			// if Buffer is NULL or Invalid Address, It can bring a bug check
			// 0x1e.
			//
			NdisGetNextBuffer(Buffer, &Buffer);
			if(Buffer == NULL) return PASS;
			NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);
			if(VirtualAddress != NULL && Length >= UDP_HEADER_LENGTH)
			{
				pUdpHeader = (PUDP_HEADER)(VirtualAddress);
			}
			else
			{
				return PASS;
			}
		}
		else
		{
			pUdpHeader = (PUDP_HEADER)((unsigned long)pIpHeader + HeaderLength);
		}

		pBiosBuffer = NULL;
		if(Buffer != NULL)
		{
			NdisGetNextBuffer(Buffer, &Buffer);
			if(Buffer != NULL)
			{
				NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);
				if(VirtualAddress != NULL && Length >= NETBIOS_MIN_PACKET_SIZE)
					pBiosBuffer = (void*)VirtualAddress;
			}
		}


		//
		// 调用 CheckUdp 对封包的合法性进行审查
		//
		return CheckUdp(pIpHeader, pUdpHeader, IsSend, TotalPacketLength, pBiosBuffer);

	case PROTOCOL_ICMP:
		//
		// 解析 ICMP
		//
		if((Length - HeaderLength) < ICMP_HEADER_LENGTH)
		{

			NdisGetNextBuffer(Buffer, &Buffer);
			if(Buffer == NULL) return PASS;
			NdisQueryBufferSafe(Buffer, &VirtualAddress, &Length, HighPagePriority);
			if(VirtualAddress != NULL && Length >= ICMP_HEADER_LENGTH)
				pIcmpHeader = (PICMP_HEADER)(VirtualAddress);
			else
				return PASS;
		}
		else
		{
			pIcmpHeader = (PICMP_HEADER)((unsigned long)pIpHeader + HeaderLength);
		}

		//
		// 调用 CheckIcmp 对封包的合法性进行审查
		//
		return CheckIcmp(pIpHeader, pIcmpHeader, IsSend, TotalPacketLength);

	case PROTOCOL_IGMP:
	default:
		break;
	}
*/
	return PASS;
	
}

/*
int CheckRecv(
    IN PVOID HeaderBuffer,
    IN UINT HeaderBufferSize,
    IN PVOID LookAheadBuffer,
    IN UINT LookaheadBufferSize,
    IN UINT PacketSize
)
{
 	WORD EthernetFrameType;
	WORD LengthCount;
	PIP_HEADER pIpHeader;
	PETHERNET_FRAME pEthernetFrame;

	if(HeaderBufferSize < ETHERNET_FRAME_LENGTH) 
		return PASS;

	// 解析Ethernet Frame
	//
	pEthernetFrame = (PETHERNET_FRAME)HeaderBuffer;
	EthernetFrameType = ntohs(pEthernetFrame->FrameType);
	if(EthernetFrameType != ETHERNET_FRAME_TYPE_TCPIP
		|| LookaheadBufferSize < IP_HEADER_LENGTH)
		return PASS;

	// 解析Ip Header
	//
	pIpHeader = (PIP_HEADER)LookAheadBuffer;
	LengthCount = pIpHeader->HeaderLength * HEADER_LENGTH_MULTIPLE;
	if(LengthCount == 0)
		return PASS;

	switch(pIpHeader->Protocol)
	{
	case PROTOCOL_TCP:
		// 解析Tcp Header
		//
		if(LookaheadBufferSize < (UINT)(LengthCount + TCP_HEADER_LENGTH))
			return PASS;
		return CheckTcp(pIpHeader
			, (PTCP_HEADER)((char*)LookAheadBuffer + LengthCount)
			, FALSE
			, PacketSize + HeaderBufferSize
			, (PVOID)LookaheadBufferSize
			);

	case PROTOCOL_UDP:
		// 解析 Udp Header
		//
		if(LookaheadBufferSize < (UINT)(LengthCount + UDP_HEADER_LENGTH))
			return PASS;
		return CheckUdp(pIpHeader
			, (PUDP_HEADER)((char*)LookAheadBuffer + LengthCount)
			, FALSE
			, PacketSize + HeaderBufferSize
			, (PVOID)LookaheadBufferSize
			);

	case PROTOCOL_ICMP:
		//
		// 解析Icmp Header
		//
		if(LookaheadBufferSize < (UINT)(LengthCount + ICMP_HEADER_LENGTH))
			return PASS;
		return CheckIcmp(pIpHeader
			, (PICMP_HEADER)((char*)LookAheadBuffer + LengthCount)
			, FALSE
			, PacketSize + HeaderBufferSize
			);

	case PROTOCOL_IGMP:
	default:
		break;
	}
	return PASS;
}
*/