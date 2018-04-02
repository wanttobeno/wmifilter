#ifndef STRUCT_HELP_H__
#define  STRUCT_HELP_H__  1
#include <ntifs.h>

struct _NDIS_OPEN_BLOCK
{
	PNDIS_MAC_BLOCK             MacHandle;          // pointer to our MAC  
	NDIS_HANDLE                 MacBindingHandle;   // context when calling MacXX funcs  
	PNDIS_ADAPTER_BLOCK         AdapterHandle;      // pointer to our adapter  
	PNDIS_PROTOCOL_BLOCK        ProtocolHandle;     // pointer to our protocol  
	NDIS_HANDLE                 ProtocolBindingContext;// context when calling ProtXX funcs  
	PNDIS_OPEN_BLOCK            AdapterNextOpen;    // used by adapter's OpenQueue  
	PNDIS_OPEN_BLOCK            ProtocolNextOpen;   // used by protocol's OpenQueue  
	PNDIS_OPEN_BLOCK            NextGlobalOpen;
	BOOLEAN                     Closing;            // TRUE when removing this struct  
	BOOLEAN                     Unbinding;          // TRUE when starting to unbind the adapter  
	BOOLEAN                     NoProtRsvdOnRcvPkt; // Reflect the protocol_options  
	BOOLEAN                     ProcessingOpens;
	PNDIS_STRING                BindDeviceName;
	KSPIN_LOCK                  SpinLock;           // guards Closing  
	PNDIS_STRING                RootDeviceName;

	//  
	// These are optimizations for getting to MAC routines. They are not  
	// necessary, but are here to save a dereference through the MAC block.  
	//  
	union
	{
		SEND_HANDLER            SendHandler;
		WAN_SEND_HANDLER        WanSendHandler;
	};
	TRANSFER_DATA_HANDLER       TransferDataHandler;

	//  
	// These are optimizations for getting to PROTOCOL routines.  They are not  
	// necessary, but are here to save a dereference through the PROTOCOL block.  
	//  
	SEND_COMPLETE_HANDLER       SendCompleteHandler;
	TRANSFER_DATA_COMPLETE_HANDLER TransferDataCompleteHandler;
	RECEIVE_HANDLER             ReceiveHandler;
	RECEIVE_COMPLETE_HANDLER    ReceiveCompleteHandler;

	//  
	// Extentions to the OPEN_BLOCK since Product 1.  
	//  
	union
	{
		RECEIVE_HANDLER         PostNt31ReceiveHandler;
		WAN_RECEIVE_HANDLER     WanReceiveHandler;
	};
	RECEIVE_COMPLETE_HANDLER    PostNt31ReceiveCompleteHandler;

	//  
	// NDIS 4.0 extensions  
	//  
	RECEIVE_PACKET_HANDLER      ReceivePacketHandler;
	SEND_PACKETS_HANDLER        SendPacketsHandler;

	//  
	// More NDIS 3.0 Cached Handlers  
	//  
	RESET_HANDLER               ResetHandler;
	REQUEST_HANDLER             RequestHandler;
	RESET_COMPLETE_HANDLER      ResetCompleteHandler;
	STATUS_HANDLER              StatusHandler;
	STATUS_COMPLETE_HANDLER     StatusCompleteHandler;
	REQUEST_COMPLETE_HANDLER    RequestCompleteHandler;
};



#endif  //STRUCT_HELP_H__