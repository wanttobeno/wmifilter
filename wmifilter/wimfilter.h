

#define NT_DEVICE_NAME L"\\Device\\wmifilter"
#define DOS_DEVICE_NAME L"\\DosDevices\\wmifiter"

NTSTATUS IoDispatch( PDEVICE_OBJECT pDeviceObject, PIRP pIrp );
void UnLoad( PDRIVER_OBJECT theDriverObject );
NTSTATUS MyIoDeviceControl( IN PDEVICE_OBJECT pDeviceObject, PIRP pIrp );
NTSTATUS MyShutdown( IN PDEVICE_OBJECT pDeviceObject, PIRP pIrp );
NTSTATUS Init(PUNICODE_STRING pRegistryPath);

extern BOOLEAN bAutoStart;



