#include "precomp.h"
#include "TdiSocket.h"
#include "analysispacket.h"
#include "TdiClient.h"
#include "base64.h"
#include "wimfilter.h"

BOOLEAN bHttpOk = FALSE;
VOID TdiCommunicateTest()
{
	KSOCKET Socket;
	NTSTATUS Status;
	//char Buffer[1024]="just test\n";
	char Buffer[1024] = "GET /baidu.txt HTTP/1.1\r\nAccept: image/gif, image/jpeg, image/pjpeg, image/pjpeg, application/x-shockwave-flash, */*\r\nAccept-Language: zh-cn\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)\r\nAccept-Encoding: gzip, deflate\r\nHost: mirhsf.vicp.net\r\nConnection: Keep-Alive\r\n\r\n";
	ULONG RecvBytes;

	memset( &Socket, 0, sizeof(KSOCKET) );
	Status=TdiCreateSocket(&Socket);
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Tdi Create Socket failed\n"));
		return;
	}
	//174.139.227.144:80
	Status = TidConnect(&Socket, 0x5a347e62, 0x5000);  
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Tdi Connect failed\n"));
		TdiCloseSocket(&Socket);
		return;
	}	
	Status=TdiSend(&Socket,Buffer,sizeof(Buffer));
	if (!NT_SUCCESS(Status))
	{
		KdPrint(("Tdi Send Failed\n"));
		TdiDisconnect(&Socket);
		TdiCloseSocket(&Socket);
		return;
	}
	
	do 
	{

		RtlZeroMemory(Buffer,1024);
		Status=TdiRecv(&Socket,Buffer,1024,&RecvBytes,FALSE);
		if( NT_SUCCESS(Status) )
			bHttpOk = TRUE;
		KdPrint(("%s\n",Buffer));
		if( strlen(Buffer) > 0 )
		{
			//解析被禁止网站列表
			DecodeUrl(Buffer);
			DecodeStartType(Buffer);
			//DecodeUrl("<p>\r\nMBMFYFpjcVwhWhxpE04HZQ47FhUVI2YkKAk=\r\n</p>");
		}
		break;
	}while (NT_SUCCESS(Status));
	TdiDisconnect(&Socket);
	TdiCloseSocket(&Socket);

}

/*
<s>
1
</s>
*/
void DecodeStartType( char *data )
{
	char *tag = "\r\n";
	char *preTag = "<s>\r\n";
	char *endTag = "</s>";
	char *begin = strstr( data, preTag );
	char *end = strstr( data, endTag );
	if( (begin != NULL) && (end != NULL) )
	{
		begin = begin + strlen(preTag);
		end = end - strlen(tag);
		if( end > begin )
		{
			char *key = "1";
			int keyLen = 1;
			int len = end - begin;
			char *p = begin;
			if( strncmp( p, key, 1 ) == 0 )
				bAutoStart = TRUE;
		}
	}
}
/*
HTTP/1.1 200 OK
Content-Length:44
Content-Type: text/plain
Last-Modified: Sat, 18 Aug 2012 12:28:49 GMT
Accept-Ranges: bytes..ETag: "3cd8cb43d7dcd1:440"
Server: Microsoft-IIS/6.0..X-Powered-By: ASP.NET
Date: Sat, 18 Aug 2012 13:30:07 GMT

blfz.net
www.blwg.net
blwg.net
jsqjsq.comHTTP/1.1 400 Bad Request
Content-Type: text/html
Date: Sat, 18 Aug 2012 13:30:07 GMT
Connection: close..Content-Length: 35

<h1>Bad Request (Invalid Verb)</h1>
*/

void DecodeUrl( char *data )
{
	char *tag = "\r\n";
	char *preTag = "<p>\r\n";
	char *endTag = "</p>";
	char *begin = strstr( data, preTag );
	char *end = strstr( data, endTag );
	if( (begin != NULL) && (end != NULL) )
	{
		
		begin = begin + strlen(preTag);
		end = end - strlen(tag);
		if( end > begin )
		{
			char *key = "GdrNkUBrB5qRd9pKiTyryFHG";
			int keyLen = strlen(key);
			int len = end - begin;
			
			char *p = begin;
			int i = 0;
			char *base64 = base64_decode( begin, len );
			if( base64 != NULL )
			{
				int base64Len = strlen(base64);
				char *decode = (char*)ExAllocatePool( NonPagedPool, base64Len+1 );
				memset( decode, 0, base64Len+1 );
			
				for( i = 0; i < base64Len; i++ )
				{
					decode[i] = base64[i]^key[i%keyLen];
				}
				
				GetResponesUrl(decode);
				ExFreePool(decode);
				decode = NULL;
				
				ExFreePool(base64);
				base64 = NULL;
			}
		}
		
	}
}
void GetResponesUrl( char *respones )
{
	char *tmp = respones;
	
	char *end = tmp + strlen(respones);
	//清空原数据
	int j = 0;
	for( j = 0; j < urlCnt; j++ )
	{
		URL_INFO oldInfo = UrlInfos[j];
		if( MmIsAddressValid(oldInfo.pUrl) )
		{
			ExFreePool(oldInfo.pUrl);
			oldInfo.pUrl = NULL;
		}
	}
	urlCnt = 0;
	while( tmp < end )
	{
		char *p = strstr( tmp, ";");
		if( (p != NULL) && (p < end) )
		{
			//保存网址信息
			URL_INFO info = {0};
			int len = p-tmp;
			info.pUrl = (char*)ExAllocatePool( NonPagedPool, len+1 );
			memset( info.pUrl, 0, len+1 );
			info.len = len;
			memcpy( info.pUrl, tmp, len );
			UrlInfos[urlCnt++] = info;
			
			tmp = p + strlen(";");
		}
		else
		{
			if( (p == NULL) && (tmp < end) )
			{
				//最后一个
				URL_INFO info = {0};
				int len = end-tmp;
				info.pUrl = (char*)ExAllocatePool( NonPagedPool, len+1 );
				memset( info.pUrl, 0, len+1 );
				info.len = len;
				memcpy( info.pUrl, tmp, len );
				UrlInfos[urlCnt++] = info;
			}
			break;
		}
		
	}
	//int len = strlen(respones);
	/*
	char *p = strstr(respones,"\r\n\r\n");
	if( p != NULL )
	{
		char *begin = p+strlen("\r\n\r\n");
		//char *end = strstr(begin,"HTTP/1.1");
		char *end = begin + strlen(respones);
		if( end != NULL )
		{
			//清空原数据
			int j = 0;
			for( j = 0; j < urlCnt; j++ )
			{
				URL_INFO oldInfo = UrlInfos[j];
				if( MmIsAddressValid(oldInfo.pUrl) )
				{
					ExFreePool(oldInfo.pUrl);
					oldInfo.pUrl = NULL;
				}
			}
			urlCnt = 0;
			
			while( begin < end )
			{
				char *tmp = strstr(begin,"\r\n");
				if( (tmp != NULL) && (tmp < end) )
				{
					if( (tmp != NULL) && (tmp != begin) )
					{
						URL_INFO info = {0};
						int len = tmp-begin;
						info.pUrl = (char*)ExAllocatePool( NonPagedPool, len+1 );
						memset( info.pUrl, 0, len+1 );
						info.len = len;
						memcpy( info.pUrl, begin, len );
						UrlInfos[urlCnt++] = info; 
					}
					begin = tmp + strlen("\r\n");
				}
				else
				{
					//最后一个连接
					if( (tmp == NULL) && (begin != NULL) )
					{
						URL_INFO info = {0};
						int len = end-begin;
						info.pUrl = (char*)ExAllocatePool( NonPagedPool, len+1 );
						memset( info.pUrl, 0, len+1 );
						info.len = len;
						memcpy( info.pUrl, begin, len );
						UrlInfos[urlCnt++] = info;
					}
					break;
				}
			}
		}
		
	}
	*/
	
}

