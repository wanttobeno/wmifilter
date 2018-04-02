#define DELAY_ONE_MICROSECOND (-10)
#define DELAY_ONE_MILLISECOND (DELAY_ONE_MICROSECOND*1000)

typedef enum
{
	SYSTEM_THREAD_DETECT,
	IMAGELOAD_NOTIFY_DETECT,
	CMP_CALLBACK_DETECT,
	IO_TIMER_DETECT
}DETECT_TYPE;
NTSTATUS InitMonitor(PDEVICE_OBJECT pDeviceObject);//³õÊ¼»¯¼à¿Ø
NTSTATUS CreateShutdownNotify( PDEVICE_OBJECT pDeviceObject );

void MonitorDetect( DETECT_TYPE type );

void MyIoTimer( PDEVICE_OBJECT  pDeviceObject, PVOID  Context );
NTSTATUS MonitorByIoTimer( PDEVICE_OBJECT pDeviceObject );
NTSTATUS MyCmpCallback(PVOID  CallbackContext,PVOID  Argument1,PVOID  Argument2 );
NTSTATUS MonitorByCmpCallbackNotify();
void MyLoadImageNotify( PUNICODE_STRING  FullImageName, HANDLE  ProcessId, PIMAGE_INFO  ImageInfo );
NTSTATUS MonitorByImageLoadNotify();
void ThreadProc( PVOID  StartContext );
NTSTATUS MonitorBySystemThread();
void enableMonitor( BOOLEAN enable );
extern NDIS_SPIN_LOCK	gMonitorSpinLock;

BOOLEAN IsShowdownCallbackExist(PVOID pShutdownPacket, PDEVICE_OBJECT pDeviceObject);
BOOLEAN IsIoTimerCallbackExist( PVOID pIopTimerQueueHead, PVOID pIoTimer );
BOOLEAN IsCmpRegisterCallbackExist( PVOID pCallbackListHeader, PVOID pCallbackAddr );
BOOLEAN IsLoadImageCallbackExist( PVOID pPsLoadImageNotifyArray, PVOID pNotifyAddr );
BOOLEAN IsThreadCallbackExist( PEPROCESS pSystemEProcess, PVOID pStartRoutine );

