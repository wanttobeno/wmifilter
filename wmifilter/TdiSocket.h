#ifndef _INCLUDE_TDI_SOCKET
#define _INCLUDE_TDI_SOCKET

typedef struct _KSOCKET
{
	PFILE_OBJECT                TransportAddress;
	HANDLE                        TransportAddressHandle;
	PFILE_OBJECT                ConnectionFile;
	HANDLE                        ConnectionFileHandle;
	BOOLEAN                        Connected;
}KSOCKET, * PKSOCKET;




NTSTATUS TdiCreateSocket(PKSOCKET Socket);


NTSTATUS TidConnect(PKSOCKET Socket, 
					ULONG Address, 
					USHORT Port);

NTSTATUS TdiDisconnect(PKSOCKET Socket);


NTSTATUS TdiSend(PKSOCKET Socket, 
				 PVOID Buffer, 
				 ULONG Length);

NTSTATUS TdiRecv(PKSOCKET Socket, 
				 PVOID Buffer, 
				 ULONG Size, 
				 ULONG *BytesReceived, 
				 BOOLEAN ReceivePeek);

VOID TdiCloseSocket(PKSOCKET Socket);






#endif

