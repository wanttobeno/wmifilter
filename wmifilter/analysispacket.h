#define TAG 'ImPa'

typedef struct HTTP_INFO
{
	int begin_offset;
	int end_offset;
}HTTP_INFO, *PHTTP_INFO;

typedef struct _URL_INFO
{
	char* pUrl;
	int  len;
}URL_INFO, *PURL_INFO;

typedef struct _DEAL_INFO
{

	URL_INFO UrlInfo;
	PKEVENT  pKEvent;
	BOOLEAN  bSafe;
	BOOLEAN  bDealing;
}DEAL_INFO, *PDEAL_INFO;

typedef struct _WAITING_INFO
{
	ULONG SeqNum;
	char* pUrl;
	UINT UrlLen;
	char* pHost;
	UINT HostLen;
	char* pRefer;
	UINT ReferLen;
	UINT state;
}WAITING_INFO, *PWAITING_INFO;
// 
// 过滤结果变量
//

typedef enum{
	STATUS_PASS,
	STATUS_DROP,
	STATUS_REDIRECT,
	STATUS_NEEDDEAL
}FILTER_RESULT;


FILTER_RESULT AnalysisPacket(PNDIS_PACKET Packet, BOOLEAN bRecOrSend);
FILTER_RESULT AnalysisNetBuffer( PNET_BUFFER pNetBuffer, BOOLEAN bRecOrSend );
void CopyBytesFromNetBuffer( PNET_BUFFER NetBuffer, PDWORD cbDest, PVOID Dest );
BOOLEAN IsHttpGetMethod( char* pAppData, int AppDataLen );
HTTP_INFO GetHttpVersion( char* pAppData, HTTP_INFO HttpUrl, int AppDataLen );
HTTP_INFO GetHttpGetMethodUrl( char* pAppData, int AppDataLen );
HTTP_INFO GetHttpSubKey( char* pAppData, HTTP_INFO HttpVersion, char* pSubKey, int AppDataLen, int* state );
void GetRealUrl( char* pRealUrl, HTTP_INFO pHost, HTTP_INFO pUrl, int len, char* pAppData );



BOOLEAN IsFindSubKey( char* pAppData, int* begin, char* pSubKey, int AppDataLen );

BOOLEAN IsWaitingPacket( ULONG SeqNum, int* WaitingIndex );

ULONG Myhtonl( ULONG hSeqNum );

BOOLEAN ExistMainUrl( char* pMainUrl, int MainUrlLen );

FILTER_RESULT NeedDealPacket( PNDIS_PACKET Packet );

extern    NDIS_SPIN_LOCK                     gWaitingSpinLock;//处理分包时的自旋锁
extern    WAITING_INFO                        WaitingInfo[100];
extern    int                                 WaitingCnt;
extern    DEAL_INFO                          DealInfos[300];
extern    int                                count;
extern 		URL_INFO													 UrlInfos[100];//危险url
extern 		int																 urlCnt;//危险url个数

