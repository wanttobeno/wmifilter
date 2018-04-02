#include <ntddk.h>
#include <tdi.h>
#include <TdiKrnl.h>
#include "TdiSocket.h"


NTSTATUS TdiCreateAddressObject(PHANDLE Handle, PFILE_OBJECT *FileObject) 
{ 
	UNICODE_STRING Name;
	OBJECT_ATTRIBUTES Attr;
	CHAR Buffer[sizeof (FILE_FULL_EA_INFORMATION) + TDI_TRANSPORT_ADDRESS_LENGTH + sizeof (TA_IP_ADDRESS)];
	PFILE_FULL_EA_INFORMATION Ea;
	IO_STATUS_BLOCK IoStatus;
	NTSTATUS Status ;
	PTA_IP_ADDRESS Sin;
	// DbgPrint(" hi in cretaaddress\n");
	RtlInitUnicodeString(&Name, L"\\Device\\Tcp"); 
	InitializeObjectAttributes(&Attr, &Name, OBJ_CASE_INSENSITIVE, 0, 0); 

	Ea = (PFILE_FULL_EA_INFORMATION)Buffer; 
	Ea->NextEntryOffset = 0; 
	Ea->Flags = 0; 
	Ea->EaNameLength = TDI_TRANSPORT_ADDRESS_LENGTH; 
	Ea->EaValueLength = sizeof (TA_IP_ADDRESS); 
	RtlCopyMemory(Ea->EaName, TdiTransportAddress, Ea->EaNameLength + 1); 

	Sin = (PTA_IP_ADDRESS)(Ea->EaName + Ea->EaNameLength + 1); 
	Sin->TAAddressCount = 1; 
	Sin->Address[0].AddressLength = TDI_ADDRESS_LENGTH_IP; 
	Sin->Address[0].AddressType = TDI_ADDRESS_TYPE_IP; 
	Sin->Address[0].Address[0].sin_port = 0; 
	Sin->Address[0].Address[0].in_addr = 0; 
	RtlZeroMemory(Sin->Address[0].Address[0].sin_zero, sizeof(Sin->Address[0].Address[0].sin_zero)); 

	Status = ZwCreateFile(Handle, 
		0, 
		&Attr, 
		&IoStatus, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		0, 
		FILE_OPEN, 
		0, 
		Ea, 
		sizeof(Buffer)); 
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("CreateAddress->ZwCreateFile return failed!!\n"));
		return Status; 
	}
	Status=ObReferenceObjectByHandle(*Handle, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		KernelMode, 
		(PVOID *)FileObject, 
		0);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(*Handle);
	}

	return Status;

}


NTSTATUS TdiCreateConnectionObject(PHANDLE Handle, PFILE_OBJECT *FileObject) 
{ 
	IO_STATUS_BLOCK IoStatus; 
	NTSTATUS Status;
	UNICODE_STRING Name; 
	OBJECT_ATTRIBUTES Attr;
	char Buffer[sizeof(FILE_FULL_EA_INFORMATION) + TDI_CONNECTION_CONTEXT_LENGTH + 300] = {0};
	PFILE_FULL_EA_INFORMATION Ea ;

	// DbgPrint("hi in createconnection\n");
	RtlInitUnicodeString(&Name, L"\\Device\\Tcp"); 
	InitializeObjectAttributes(&Attr, &Name, OBJ_CASE_INSENSITIVE, 0, 0); 

	Ea = (PFILE_FULL_EA_INFORMATION)&Buffer;
	RtlCopyMemory(Ea->EaName, TdiConnectionContext, TDI_CONNECTION_CONTEXT_LENGTH);
	Ea->EaNameLength = TDI_CONNECTION_CONTEXT_LENGTH; 
	Ea->EaValueLength =TDI_CONNECTION_CONTEXT_LENGTH; 


	Status= ZwCreateFile(Handle, 
		GENERIC_READ | GENERIC_WRITE, 
		&Attr, 
		&IoStatus, 
		0, 
		FILE_ATTRIBUTE_NORMAL, 
		FILE_SHARE_READ, 
		FILE_OPEN, 
		0, 
		Ea, 
		sizeof(Buffer)); 
	if (!NT_SUCCESS(Status)) 
	{
		KdPrint(("ZwCreateFile return failed!!\n"));
		return Status; 
	}
	Status=ObReferenceObjectByHandle(*Handle,
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		KernelMode, 
		(PVOID *)FileObject, 
		0);
	if (!NT_SUCCESS(Status))
	{
		ZwClose(*Handle);
		return Status;
	}

	return Status;

}



/*************************************************************************************************
/*The client must make the associate-address request before it makes a connection to the remote node 
/*把FileObject,Address关联...
/* Associate endpoint with address
/*************************************************************************************************/
NTSTATUS TdiBind(PFILE_OBJECT ConnectionObject, HANDLE AddressHandle) 
{ 
	KEVENT Event; 
	PDEVICE_OBJECT DeviceObject;
	IO_STATUS_BLOCK IoStatus;
	PIRP Irp ;
	NTSTATUS Status;
	// Define a completion event

	KeInitializeEvent(&Event, NotificationEvent, FALSE); 
	DeviceObject = IoGetRelatedDeviceObject(ConnectionObject); 
	if (DeviceObject==NULL)
	{
		return STATUS_UNSUCCESSFUL;
	}
	Irp = TdiBuildInternalDeviceControlIrp(TDI_ASSOCIATE_ADDRESS, DeviceObject, FileObject, &Event, &IoStatus); 
	/*
	TdiBuildAssociateAddress sets IRP_MJ_INTERNAL_DEVICE_CONTROL as the MajorFunction and TDI_ASSOCIATE_ADDRESS 
	as the MinorFunction codes in the transport's I/O stack location of the given IRP.*/
	if (Irp == 0) 
		return STATUS_INSUFFICIENT_RESOURCES; 
	TdiBuildAssociateAddress(Irp, DeviceObject, ConnectionObject, 0, 0, AddressHandle); 
	Status = IoCallDriver(DeviceObject, Irp); 
	if (Status == STATUS_PENDING) 
		Status = KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, 0);

	return Status == STATUS_SUCCESS ? IoStatus.Status : Status; 
}


VOID TdiCloseOpenHandle(HANDLE hTdiHandle, 

						PFILE_OBJECT TdiFileObject) 

{ 

	NTSTATUS Status = STATUS_SUCCESS; 
	if (TdiFileObject)
	{
		ObDereferenceObject(TdiFileObject); 
	}
	if (hTdiHandle)
	{

		ZwClose(hTdiHandle); 
	}
}


VOID TdiCloseSocket(PKSOCKET Socket)
{

	TdiCloseOpenHandle(Socket->ConnectionFileHandle,Socket->ConnectionFile);
	TdiCloseOpenHandle(Socket->TransportAddressHandle,Socket->TransportAddress);
}


NTSTATUS TdiCreateSocket(PKSOCKET Socket)
{
	NTSTATUS Status = STATUS_INVALID_PARAMETER;
	if (!Socket)
	{
		return Status;
	}
	Status=TdiCreateAddressObject(&Socket->TransportAddressHandle,&Socket->TransportAddress);
	if (!NT_SUCCESS(Status))
	{
		goto _EXIT;
	}

	Status=TdiCreateConnectionObject(&Socket->ConnectionFileHandle,&Socket->ConnectionFile);
	if (!NT_SUCCESS(Status))
	{
		goto _EXIT;
	}

	Status=TdiBind(Socket->ConnectionFile,Socket->TransportAddressHandle);

	if (!NT_SUCCESS(Status))
	{
		goto _EXIT;
	}

	return Status;
_EXIT:
	TdiCloseSocket(Socket);
	return Status;


}

/*********************************************************************************/
/*创建连接
/*Connect to the remote controller
/*
/*********************************************************************************/

NTSTATUS TidConnect(PKSOCKET Socket, ULONG Address, USHORT Port) 
{ 
	KEVENT Event; 
	PDEVICE_OBJECT DeviceObject;
	IO_STATUS_BLOCK IoStatus; 
	PIRP Irp;
	TA_IP_ADDRESS RemoteAddr;
	TDI_CONNECTION_INFORMATION RequestInfo;
	PTDI_ADDRESS_IP pTdiAddressIp;
	NTSTATUS Status;


	KeInitializeEvent(&Event, NotificationEvent, FALSE); 
	DeviceObject = IoGetRelatedDeviceObject(Socket->ConnectionFile); 
	//// build connection packet
	Irp = TdiBuildInternalDeviceControlIrp(TDI_CONNECT, DeviceObject, ConnectionObject, &Event, &IoStatus); 
	if (Irp == 0)
		return STATUS_INSUFFICIENT_RESOURCES; 

	// Initialize controller data
	RemoteAddr.TAAddressCount=1;
	RemoteAddr.Address[0].AddressLength=TDI_ADDRESS_LENGTH_IP;
	RemoteAddr.Address[0].AddressType=TDI_ADDRESS_TYPE_IP;

	RemoteAddr.Address[0].Address[0].sin_port =Port;
	RemoteAddr.Address[0].Address[0].in_addr =Address;

	RequestInfo.Options=0;
	RequestInfo.OptionsLength=0;
	RequestInfo.UserData=0;
	RequestInfo.UserDataLength=0;
	RequestInfo.RemoteAddress=&RemoteAddr;
	RequestInfo.RemoteAddressLength=sizeof(RemoteAddr);

	TdiBuildConnect(Irp, DeviceObject, Socket->ConnectionFile, 0, 0, 0, &RequestInfo, 0); 
	Status = IoCallDriver(DeviceObject, Irp); 
	if (Status == STATUS_PENDING) 
		KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, 0); 

	Status=IoStatus.Status;
	if (NT_SUCCESS(Status))
	{
		Socket->Connected=TRUE;
	}


	return Status;

}


NTSTATUS TdiDisAssociateTransportAndConnection(PFILE_OBJECT ConnectionObject) 

{ 

	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES; 

	PIRP Irp; 

	IO_STATUS_BLOCK IoStatusBlock = {0}; 

	PDEVICE_OBJECT DeviceObject; 

	KEVENT Event;

	KeInitializeEvent(&Event,NotificationEvent, FALSE);

	DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

	Irp = TdiBuildInternalDeviceControlIrp(TDI_DISASSOCIATE_ADDRESS, 

		DeviceObject, ConnectionObject, 

		&Event, &IoStatusBlock); 


	if(Irp) 

	{ 

		TdiBuildDisassociateAddress(Irp, DeviceObject, 

			ConnectionObject, NULL, NULL); 


		Status = IoCallDriver(DeviceObject, Irp); 



		if(Status == STATUS_PENDING) 

		{ 

			KeWaitForSingleObject(&Event, 

				Executive, KernelMode, FALSE, NULL); 

			Status = IoStatusBlock.Status; 

		} 


	} 


	return Status; 

} 


NTSTATUS TdiDisconnect(PKSOCKET Socket) 
{ 
	KEVENT Event;
	NTSTATUS Status;
	PDEVICE_OBJECT DeviceObject;
	IO_STATUS_BLOCK IoStatus; 
	PIRP Irp;

	Status=TdiDisAssociateTransportAndConnection(Socket->ConnectionFile);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}

	KeInitializeEvent(&Event, NotificationEvent, FALSE); 
	DeviceObject = IoGetRelatedDeviceObject(Socket->ConnectionFile); 
	Irp = TdiBuildInternalDeviceControlIrp(TDI_DISCONNECT, DeviceObject, ConnectionObject, &Event, &IoStatus); 
	if (Irp == 0)
		return STATUS_INSUFFICIENT_RESOURCES; 
	TdiBuildDisconnect(Irp, DeviceObject, Socket->ConnectionFile, 0, 0, 0, TDI_DISCONNECT_RELEASE, 0, 0); 
	Status = IoCallDriver(DeviceObject, Irp); 
	if (Status == STATUS_PENDING) 
		KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, 0); 

	Status=IoStatus.Status;

	return Status; 
}


NTSTATUS TdiSend(PKSOCKET Socket, PVOID Buffer, ULONG Length) 
{ 
	KEVENT Event; 
	PDEVICE_OBJECT DeviceObject ;
	IO_STATUS_BLOCK IoStatus; 
	PIRP Irp;
	PMDL Mdl;
	NTSTATUS Status;

	KeInitializeEvent(&Event, NotificationEvent, FALSE); 

	DeviceObject = IoGetRelatedDeviceObject(Socket->ConnectionFile); 
	Irp = TdiBuildInternalDeviceControlIrp(TDI_SEND, DeviceObject, ConnectionObject, &Event, &IoStatus); 
	if (Irp == 0) 
		return STATUS_INSUFFICIENT_RESOURCES; 

	Mdl = IoAllocateMdl(Buffer, Length, FALSE, FALSE, Irp); 
	if (Mdl == 0)
		return STATUS_INSUFFICIENT_RESOURCES; 
	__try 
	{ 
		MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);
	}__except (EXCEPTION_EXECUTE_HANDLER) 
	{ 
		IoFreeMdl(Mdl); 
		Mdl = NULL;
	}


	TdiBuildSend(Irp, DeviceObject, Socket->ConnectionFile, 0, 0, Mdl, 0, Length); 
	Status = IoCallDriver(DeviceObject, Irp); 
	if (Status == STATUS_PENDING) 
		KeWaitForSingleObject(&Event, UserRequest, KernelMode, FALSE, 0); 

	Status=IoStatus.Status;

	return Status;
}






NTSTATUS TdiRecv(PKSOCKET Socket, PVOID Buffer, ULONG Size, ULONG *BytesReceived, BOOLEAN ReceivePeek)
{
	PDEVICE_OBJECT    DeviceObject;
	PFILE_OBJECT    ConnectionObject;
	PIRP            Irp = NULL;
	NTSTATUS        Status = STATUS_TIMEOUT;
	PMDL            Mdl;
	ULONG            Flags;
	IO_STATUS_BLOCK IoStatus;

	KEVENT  Event;


	if (!Socket)
		return STATUS_INVALID_PARAMETER;

	// set parameters
	ConnectionObject = Socket->ConnectionFile;

	DeviceObject = IoGetRelatedDeviceObject(ConnectionObject);

	*BytesReceived = 0;

	if (ReceivePeek)
		Flags = TDI_RECEIVE_PEEK;
	else
		Flags = TDI_RECEIVE_NORMAL;
	// initialize event and device
	KeInitializeEvent(&Event, NotificationEvent, FALSE);    


	Irp=TdiBuildInternalDeviceControlIrp(TDI_RECEIVE, DeviceObject, ConnectionObject, &Event, &IoStatus);

	if (!Irp)
		return STATUS_INSUFFICIENT_RESOURCES;

	// build mdl
	Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, NULL);
	if (!Mdl)
	{
		Status = STATUS_INSUFFICIENT_RESOURCES;
		IoFreeIrp (Irp);
		return Status;
	}

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoWriteAccess);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl (Mdl);
		IoFreeIrp (Irp);
		Status = STATUS_UNSUCCESSFUL;
		return Status;
	}
	Mdl->Next = NULL;

	// build irp (this set completion routine too)
	TdiBuildReceive (Irp, DeviceObject,ConnectionObject,NULL, NULL,Mdl,Flags,Size);

	// call tcp
	Status = IoCallDriver(DeviceObject, Irp);
	if (Status == STATUS_PENDING)
	{

		Status = KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}

	*BytesReceived = IoStatus.Information;

	Status=IoStatus.Status;


	return Status;
}






NTSTATUS SetEventHandler(PFILE_OBJECT AddressObject, 

						 LONG InEventType, PVOID InEventHandler, PVOID InEventContext) 

{ 

	NTSTATUS Status = STATUS_INSUFFICIENT_RESOURCES; 

	PIRP Irp; 

	IO_STATUS_BLOCK IoStatusBlock = {0}; 

	PDEVICE_OBJECT DeviceObject; 

	LARGE_INTEGER TimeOut = {0}; 

	ULONG NumberOfSeconds = 60*3; 
	KEVENT Event;
	KeInitializeEvent(&Event, 

		NotificationEvent, FALSE);


	DeviceObject = IoGetRelatedDeviceObject(AddressObject); 


	Irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER, 

		DeviceObject, AddressObject, &Event, 

		&IoStatusBlock); 


	if(Irp) 

	{ 



		TdiBuildSetEventHandler(Irp, DeviceObject, AddressObject, 

			NULL, NULL, InEventType, InEventHandler, InEventContext); 


		Status = IoCallDriver(DeviceObject, Irp); 



		if(Status == STATUS_PENDING) 

		{ 

			KeWaitForSingleObject(&Event, 

				Executive, KernelMode, FALSE, NULL); 




			Status = IoStatusBlock.Status; 

		} 


	} 


	return Status; 

} 


NTSTATUS TdiSetEventHandler(
							PFILE_OBJECT FileObject,
							LONG EventType,
							PVOID Handler,
							PVOID Context)

{
	PDEVICE_OBJECT DeviceObject;
	IO_STATUS_BLOCK Iosb;
	NTSTATUS Status;
	KEVENT Event;
	PIRP Irp;



	if (!FileObject) {

		return STATUS_INVALID_PARAMETER;
	}

	DeviceObject = IoGetRelatedDeviceObject(FileObject);
	if (!DeviceObject) {
		return STATUS_INVALID_PARAMETER;
	}

	KeInitializeEvent(&Event, NotificationEvent, FALSE);

	Irp = TdiBuildInternalDeviceControlIrp(TDI_SET_EVENT_HANDLER,   /* Sub function */
		DeviceObject,            /* Device object */
		FileObject,              /* File object */
		&Event,                  /* Event */
		&Iosb);                  /* Status */
	if (!Irp)
		return STATUS_INSUFFICIENT_RESOURCES;



	TdiBuildSetEventHandler(Irp,
		DeviceObject,
		FileObject,
		NULL,
		NULL,
		EventType,
		Handler,
		Context);

	Status = IoCallDriver(DeviceObject,Irp);

	return Status;
}


//使用这个函数实现回调的代码如下：
// 
// Collapse
// 
// NtStatus = TdiFuncs_SetEventHandler( 
// 
// 									pTdiExampleContext->TdiHandle.pfoTransport, 
// 
// 									TDI_EVENT_RECEIVE, 
// 
// 									TdiExample_ClientEventReceive, 
// 
// 									(PVOID)pTdiExampleContext); 
// 
// 
// 
// ... 
// 
// 
NTSTATUS 
ClientEventReceive(
				   IN PVOID  TdiEventContext,
				   IN CONNECTION_CONTEXT  ConnectionContext,
				   IN ULONG  ReceiveFlags,
				   IN ULONG  BytesIndicated,
				   IN ULONG  BytesAvailable,
				   OUT ULONG  *BytesTaken,
				   IN PVOID  Tsdu,
				   OUT PIRP  *IoRequestPacket
				   )
{
	if (ReceiveFlags&TDI_RECEIVE_NORMAL)
	{
		PVOID ReceiveBuffer;
		ReceiveBuffer = ExAllocatePool(NonPagedPool, BytesAvailable);
		if (!ReceiveBuffer)
			return STATUS_INSUFFICIENT_RESOURCES;
		RtlZeroMemory(ReceiveBuffer,BytesAvailable+1);
		RtlCopyMemory(ReceiveBuffer, Tsdu, BytesAvailable);


		*BytesTaken = BytesAvailable;
		KdPrint(("%s\n",ReceiveBuffer));
	}





	return STATUS_SUCCESS;
}




