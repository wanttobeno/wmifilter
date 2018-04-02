#include "precomp.h"
#include "ntstrsafe.h"
#include "analysispacket.h"


typedef struct in_addr {
	union {
		struct { UCHAR s_b1,s_b2,s_b3,s_b4; } S_un_b;
		struct { USHORT s_w1,s_w2; } S_un_w;
		ULONG S_addr;
	} S_un;
} IN_ADDR, *PIN_ADDR, FAR *LPIN_ADDR;

typedef struct IP_HEADER
{
	unsigned char  VIHL;          // Version and IHL
	unsigned char  TOS;           // Type Of Service
	short          TotLen;        // Total Length
	short          ID;            // Identification
	short          FlagOff;       // Flags and Fragment Offset
	unsigned char  TTL;           // Time To Live
	unsigned char  Protocol;      // Protocol
	unsigned short Checksum;      // Checksum
	struct in_addr        iaSrc;  // Internet Address - Source
	struct in_addr        iaDst;  // Internet Address - Destination
}IP_HEADER, *PIP_HEADER;

typedef struct TCP_HEADER
{
	unsigned short SrcPort;
	unsigned short DestPort;
	ULONG          SeqNum;
	ULONG          AckNum;
	unsigned short LenAndRes;
	unsigned short WindowSize;
	unsigned short CheckKey;
	unsigned short UrgentPointer;
}TCP_HEADER, *PTCP_HEADER;

#define IP_OFFSET                               0x0E

//IP Protocol Types
#define PROT_ICMP                               0x01 
#define PROT_TCP                                0x06 
#define PROT_UDP                                0x11 

NDIS_SPIN_LOCK                     gWaitingSpinLock;//处理分包时的自旋锁
WAITING_INFO                        WaitingInfo[100];
int                                 WaitingCnt;
DEAL_INFO                          DealInfos[300];
int                                count;
URL_INFO													 UrlInfos[100]={0};
int																 urlCnt = 0;

//win7禁止访问网站
DWORD dw_win7UrlCnt = 4;
char *psz_win7DangeUrl[]={"blfz.net","www.blwg.net","blwg.net","jsqjsq.com"};
// 输入参数：
//	Packet： 被分析的NDIS包描述符
//	bRecOrSend: 如果是接收包，为TRUE;如果为发送包，为FALSE。
// 返回值：
//	理想的情况下，调用者通过返回值以决定如何处理NDIS包：续传、失败、转发
FILTER_RESULT AnalysisPacket(PNDIS_PACKET Packet,  BOOLEAN bRecOrSend)
{
	FILTER_RESULT status = STATUS_PASS; // 默认全部通过
	PNDIS_BUFFER NdisBuffer ;
	UINT TotalPacketLength = 0;
	UINT copysize = 0;
	UINT DataOffset = 0 ;
	UINT PhysicalBufferCount;
	UINT BufferCount   ;
	PUCHAR pPacketContent = NULL;
	PUCHAR pPacketContentTmp = NULL;
	char* tcsPrintBuf = NULL;
	PUCHAR tembuffer = NULL ; 
	UINT j;

	__try{

    
		status = NdisAllocateMemoryWithTag( &pPacketContent, 2048, TAG); 
		if( status != NDIS_STATUS_SUCCESS ){
			status = NDIS_STATUS_FAILURE ;
			__leave;
		}
		pPacketContentTmp = pPacketContent;
		NdisZeroMemory( pPacketContent, 2048 ) ;
		

		// 找到第一个Ndis_Buffer。然后通过通过NdisGetNextBuffer来获得后续的NDIS_BUFFER。
		// 如果只是找第一个节点，更快且方便的方法是调用NdisGetFirstBufferFromPacket。
		NdisQueryPacket(Packet,  // NDIS_PACKET        
			&PhysicalBufferCount,// 内存中的物理块数
			&BufferCount,		 // 多少个NDIS_BUFFER包
			&NdisBuffer,         // 将返回第一个包
			&TotalPacketLength	 // 总共的包数据长度
			);
		if( TotalPacketLength > 2048 )
		{
			status = NDIS_STATUS_FAILURE ;
			__leave;
		}
		while(TRUE){

			// 取得Ndis_Buffer中存储缓冲区的虚拟地址。
			// 这个函数的另一个版本是NdisQueryBuffer。
			// 后者在系统资源低或者甚至耗尽的时候，会产生Bug Check，导致蓝屏。h
			NdisQueryBufferSafe(NdisBuffer,
				&tembuffer,// 缓冲区地址
				&copysize, // 缓冲区大小 
				NormalPagePriority
				);

			// 如果tembuffer为NULL，说明当前系统资源匮乏。
			if(tembuffer != NULL){
				NdisMoveMemory( pPacketContent + DataOffset , tembuffer, copysize) ;			
				DataOffset += copysize;
			}

			// 获得下一个NDIS_BUFFER。
			// 如果得到的是一个NULL指针，说明已经到了链式缓冲区的末尾，我们的循环应该结束了。
			NdisGetNextBuffer(NdisBuffer , &NdisBuffer ) ;

			if( NdisBuffer == NULL )
				break ;
		}

		// 取得数据包内容后，下面将对其内容进行过滤。
		// 我们在这个函数中的实现，仅仅简单地打印一些可读的Log信息。
		if(pPacketContent[12] == 8 &&  pPacketContent[13] == 0 )  //is ip packet
		{	
			PIP_HEADER pIPHeader = (PIP_HEADER)(pPacketContent + IP_OFFSET);
			switch(pIPHeader->Protocol)
			{
			case PROT_ICMP:
				if(bRecOrSend)
					KdPrint(("Receive ICMP packet"));
				else
					KdPrint(("Send ICMP packet"));

				//
				// 取得ICMP头，做出你的过滤判断。
				// 
				break;
			case PROT_UDP:
				
				if(bRecOrSend)
					KdPrint(("Receive UDP packet"));
				else
					KdPrint(("Send UDP packet"));

				//
				// 取得UDP头，做出你的过滤判断。
				//
				
				break;
			case PROT_TCP:
				if(bRecOrSend)
				{
					KdPrint(("Receive TCP packet"));
					break;
					
				}
				else
				{//send packet
					
					PTCP_HEADER pTcpHeader = (PTCP_HEADER)( (UCHAR*)pIPHeader + ((pIPHeader->VIHL)&0xf)*4 );
					UINT HeaderLen = (((pTcpHeader->LenAndRes)&0x00f0)>>4)*4 + ((pIPHeader->VIHL)&0xf)*4 + 0xe;
				
					
					if( (DataOffset > HeaderLen) && (pTcpHeader->DestPort == 0x5000) )
					{//有应用层数据，且应用程的端口号为80
						char *pAppData = pPacketContent + HeaderLen;
						int AppDataLen = DataOffset - HeaderLen;
						
						//与应用层交互所需变量
						DEAL_INFO DealInfo = {0};
						PKEVENT pKEvent = NULL;
						UNICODE_STRING EventName;
						WCHAR ch[200];
						HANDLE hThread;
						UINT index = 0;
						
						//根据数据包SeqNum，判断是否是被等待包
						UINT WaitingIndex = 0;
						
						//存储提取后的网址
						char pRealUrl[2048] = {0};
						UINT len = 0;
						
						
						//存储提取后的refer，用于检测过滤
						char pRefer[100] = {0};
						UINT  ReferMainLen = 0;
						
						
						//网络字节序与主机字节序转换
						pTcpHeader->SeqNum = Myhtonl( pTcpHeader->SeqNum );
						
						NdisAcquireSpinLock( &gWaitingSpinLock );
						if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
						{//是等待分包
							/*
							处理方法:
							1.根据SeqNum找到存储在WaitingInfo数组中对应的那项，获取Host被分包的种类state；
							2.根据state的种类分别进行处理，将第二分包中的Host值信息提取出；
							3.将提取出的第二分包Host信息，存放在WaitingInfo中的第一分包Host信息组合，拼凑出完整的Host值，
							  并根据该值长度，做初步处理；
							4.将获得的完整Host信息与Url整合，拼凑出完整网址:Host+Url;并根据长度，做初步处理,
							  网址值存放在pRealUrl，长度len;
							5.利用goto语句跳转到，与正常包同样的处理流程中
							*/
							int state = WaitingInfo[WaitingIndex].state;

							NdisReleaseSpinLock( &gWaitingSpinLock );
							//不考虑GET命令被分成3个/3个以上包的情况
							{
							
							char* pHost = NULL;
							UINT   begin = 0;
							UINT   end   = 0;
							switch( state )
							{
								case 1:
									{//未包含键名
										int index = 0;
										begin = 0;
										for(; index < AppDataLen; index++ )
										{
											if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
											{//因为未考虑GET命令3个以上分包，所以必然成功
												end = index;
											  break;
											}
										}
										break;
									}
								case 2:
									{//包含部分键名
										int index = 0;
										BOOLEAN bFound = FALSE;
										for(; index < AppDataLen; index++ )
										{
											if( !bFound )
											{
											   if( 0x20  == pAppData[index] )
											   {
												    begin = index+1;
												    bFound = TRUE;
												    continue;
										     }
										  }
											if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
											{
												end = index;
												break;
											}
										}
										break;
									}
								case 3:
									{//包含全部键名
										int index = 0;
										BOOLEAN bFound = TRUE;
										
										for(; index < AppDataLen; index++ )
										{
											if( !bFound )
										  {
											   if( 0 == strncmp( pAppData+index, "Host:", 5 ) )
											   {
											     	begin = index+6;
												    index = index+5;
												    continue;
											   }
										  }
										  if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
										  {
										  	end = index;
										  	break;
										  }	
										}
										break;
									}
									
							}
							//查找到剩余的Host信息的起始位置，未考虑分包数 >= 3情况，必然成立
							if( end > begin )
							{
								//存储剩余的Host信息
								WAITING_INFO WaitingFstInfo = {0};
								int SecHostLen = end - begin;
								pHost = (char*)ExAllocatePool( NonPagedPool, SecHostLen+1 );
								memset( pHost, 0, SecHostLen+1 );
								strncpy( pHost, pAppData+begin, SecHostLen );
								
								//将获取的剩余Host信息与前部分Host信息整合
								NdisAcquireSpinLock( &gWaitingSpinLock );
								//重新获取WaitingIndex
								WaitingIndex = 0;
								if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
								{//必然能找到
	                /*
									int HostLen = WaitingInfo[WaitingIndex].HostLen + len;
									//这里假设Host的最大长度为2048，若超过，只取前204个字节
									if( HostLen > 2048 )
										HostLen = 2048;
									//整合Host值
									strncat( WaitingInfo[WaitingIndex].pHost+WaitingInfo[WaitingIndex].HostLen, pHost, len );
									
									WaitingInfo[WaitingIndex].HostLen = HostLen;
									*/
									
									//存储完整Host值长度
									UINT HostLen = 0;
									UINT UrlLen = 0;
									UINT FstHostLen = 0;
									
									WaitingFstInfo = WaitingInfo[WaitingIndex];
									HostLen = WaitingFstInfo.HostLen + SecHostLen;
									UrlLen = WaitingFstInfo.UrlLen;
									FstHostLen = WaitingFstInfo.HostLen;
	                if( HostLen > 2048 )
	                {
	                	HostLen = 2048;
	                }
	                
	
	                WaitingInfo[WaitingIndex].HostLen = HostLen; 
									NdisReleaseSpinLock( &gWaitingSpinLock );
									
	                //整合Host值
	                strncat( WaitingFstInfo.pHost+FstHostLen, pHost, HostLen-FstHostLen );
	                ExFreePool( pHost );
	                pHost = NULL;
	                
	                
	                //对整合后的Host做简要处理，如果是我们自己构建的检测包，直接放过
	                if( HostLen > strlen("reputation.cloudsvc.net") )
	                {
	                	if( 0 == strncmp( WaitingFstInfo.pHost, "reputation.cloudsvc.net", strlen("reputation.cloudsvc.net") ) )
	                	{//此种情况，只会出现在我们的检测包的Host值，被拆分
	                		ExFreePool( WaitingFstInfo.pHost );
					  	        ExFreePool( WaitingFstInfo.pUrl );
					  	        ExFreePool( WaitingFstInfo.pRefer );
	                		
							        return STATUS_PASS;
							      }
	                }
	                //整合网址，并存放入pRealUrl
	                len = HostLen + WaitingFstInfo.UrlLen;
							  	if( len > 2048 )
							  	{//网址长度超长
							  		if( (len-UrlLen) < 2048 )//主机域长度合格，只送检主机域
							  		{
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  			len = len-UrlLen;
							  		}
							  		else//主机域长度也超长,取Host域，第一个‘/’前的值
							  		{
							  			UINT index = 0;
							  			for(; index < len-UrlLen; index++ )
							  			{
							  				if( WaitingFstInfo.pHost[index] == '/' )
							  					break;
							  			}
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, index+1 );
							  			len = index+1;
							  		}
							  	}
							  	else
							  	{//网址不超长
							  		strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  		strncat( pRealUrl, WaitingFstInfo.pUrl, UrlLen );
							  	}
							  	//提取Refer主网址
							  	if( WaitingFstInfo.ReferLen > 0 )
							  	{
							  		//Refer:http://xxx.xxx,前面有7个无用符号
							  		UINT index = 7;
							  		for(; index < WaitingFstInfo.ReferLen; index++ )
							  		{
							  			if( WaitingFstInfo.pRefer[index] == '/' )
							  				break;
							  		}
							  		if( index < WaitingFstInfo.ReferLen )
							  			ReferMainLen = index-7;
							  		else
							  			ReferMainLen = WaitingFstInfo.ReferLen;
							  		if( ReferMainLen < 100 )
							  		  strncpy( pRefer, WaitingFstInfo.pRefer+7, ReferMainLen );
							  		else
							  			KdPrint(("ReferMainLen > 100\n"));
							  	}
									goto Position;
									/*
									//分包处理结束后，第二分包事件被激活
									//重新获取WaitingIndex
									WaitingIndex = 0;
									NdisAcquireSpinLock( &gWaitingSpinLock );
									if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
									{//必然找到
										BOOLEAN bSafe = WaitingInfo[WaitingIndex].bSafe;
										for(; WaitingIndex < WaitingCnt; WaitingIndex++ )
										    WaitingInfo[WaitingIndex] = WaitingInfo[WaitingIndex+1];
										NdisReleaseSpinLock( &gWaitingSpinLock );
										
										//释放分配的存储剩余Host信息的内存
									  ExFreePool( pHost );
										
										if( bSafe )
											return STATUS_PASS;
										else
											return STATUS_DROP;	
									}
									NdisReleaseSpinLock( &gWaitingSpinLock );								
								}
								NdisReleaseSpinLock( &gWaitingSpinLock );
										
							}
							//未经过检测返回
							//非正常状况
							if( pHost != NULL )
								ExFreePool( pHost );
							return STATUS_PASS;
							*/
						    }
						  }
							
						  }
						}
						else
						   NdisReleaseSpinLock( &gWaitingSpinLock );
						
						//不是被等待分包,判断是否为Get请求包
						if( IsHttpGetMethod(pAppData, AppDataLen ) )
						{//client请求网页

							HTTP_INFO HttpUrl = {0};
							HTTP_INFO HttpVersion = {0};
							HTTP_INFO HttpReferer = {0};
							HTTP_INFO HttpHost = {0};
							

							
							int HostLen = 0;
							int UrlLen = 0;
							int ReferLen = 0;
							
							
							//标识该分包能否提取出完成的"键名"+键值,0:完整；1:"键名"完整，键值不完整；2："键名"不完整；3：无
							int state = 0;
							
							//获取Url信息值
							HttpUrl = GetHttpGetMethodUrl( pAppData, AppDataLen );
						  //判断改包是否符合HTTP协议格式
						  if( HttpUrl.end_offset < HttpUrl.begin_offset )
							{//Url超长或不存在Url
								 return STATUS_DROP;
							}
							
							//获取HTTP版本值
							HttpVersion = GetHttpVersion( pAppData, HttpUrl, AppDataLen );
							if( HttpVersion.end_offset < HttpUrl.begin_offset )
								return STATUS_DROP;
							
							HttpReferer = GetHttpSubKey( pAppData, HttpVersion, "Referer:", AppDataLen, &state );
							HttpHost = GetHttpSubKey( pAppData, HttpVersion, "Host:", AppDataLen, &state );
							
							//提取待检验的网址
							if( HttpHost.end_offset == 0 )
								HostLen = 0;
							else
							{
							  HostLen = (HttpHost.end_offset - HttpHost.begin_offset+1);
							  HostLen = HostLen < 2048 ? HostLen: 2048;
							}
							if( HttpUrl.end_offset == 0 )
								UrlLen = 0;
							else
							{
							  UrlLen = HttpUrl.end_offset-HttpUrl.begin_offset+1;
							  UrlLen = UrlLen < 2048 ? UrlLen : 2048;
							}
							if( HttpReferer.end_offset == 0 )
								ReferLen = 0;
							else
							{
								ReferLen = HttpReferer.end_offset - HttpReferer.begin_offset+1;
								ReferLen = ReferLen < 2048 ? ReferLen : 2048;
							}
								
							//如果是我们构造的分包，直接放过
							if( HostLen > 0 )
							{
								int StrLen = strlen("reputation.cloudsvc.net");
								int CmpLen = (StrLen > HostLen ? HostLen:StrLen);
								if( 0 == strncmp( pAppData+HttpHost.begin_offset, "reputation.cloudsvc.net", CmpLen ) )
							        return STATUS_PASS;
							  
							}
							
						
							//如果分包中不包含完整的Host信息
							if( state != 0 )
							{
								/*
								处理方法：
								1.提取Host、Url、Refer信息，并根据长度做处理;
								2.根据当前包的SeqNum值，计算下一分包的SeqNum值;
								3.将上述提取的信息、下一分包值、分包种类state，保存到全局数据WaitingInfo;
								4.直接放过该数据包
								*/
								//初始化该分包信息
								WAITING_INFO WaitingFstInfo = {0};
								
								//return STATUS_PASS;
								
								WaitingFstInfo.pHost = (char*)ExAllocatePool( NonPagedPool, 2048 );
								memset( WaitingFstInfo.pHost, 0, 2048 );
								if( HostLen > 0 )
								{
									memcpy( WaitingFstInfo.pHost, pAppData+HttpHost.begin_offset, HostLen );
									WaitingFstInfo.HostLen = HostLen;
								}
								
								WaitingFstInfo.pUrl = (char*)ExAllocatePool( NonPagedPool, 2048 );
								memset( WaitingFstInfo.pUrl, 0, 2048 );
								if( UrlLen > 0 )
								{
									memcpy( WaitingFstInfo.pUrl, pAppData+HttpUrl.begin_offset, UrlLen );
									WaitingFstInfo.UrlLen = UrlLen;
							  }
							  
							  WaitingFstInfo.pRefer = (char*)ExAllocatePool( NonPagedPool, 2048 );
							  memset( WaitingFstInfo.pRefer, 0, 2048 );
							  if( ReferLen > 0 )
							  {
							  	memcpy( WaitingFstInfo.pRefer, pAppData+HttpReferer.begin_offset, ReferLen );
							  	WaitingFstInfo.ReferLen = ReferLen;
							  }
							  
							  WaitingFstInfo.SeqNum = pTcpHeader->SeqNum + AppDataLen;
							  if( (pTcpHeader->LenAndRes)&0x0300 )
							  	WaitingFstInfo.SeqNum++;
							  WaitingFstInfo.state = state;

							  
							  //存储该分包信息
							  NdisAcquireSpinLock( &gWaitingSpinLock );
							  WaitingInfo[WaitingCnt++] = WaitingFstInfo;
							  NdisReleaseSpinLock( &gWaitingSpinLock );
							  
							  return STATUS_PASS;
							  
							  /*
							  //等待分包重组
							  KeWaitForSingleObject( &kFstEvent, Executive, KernelMode, 0, 0 );
							  
							  //重组网址
							  
							  NdisAcquireSpinLock( &gWaitingSpinLock );
							  WaitingIndex = 0;
							  if( IsWaitingPacket(pTcpHeader->SeqNum+AppDataLen, &WaitingIndex) )
							  {//正常情况下应该成功
							  	 len = WaitingInfo[WaitingIndex].UrlLen + WaitingInfo[WaitingIndex].HostLen;
							  	 NdisReleaseSpinLock( &gWaitingSpinLock);
							  }
							  else 	  //非正常情况
							     NdisReleaseSpinLock( &gWaitingSpinLock);
							    
							  if( len > 0 )
							  {//只是对查找是否成功的检测，不必须判断
							  	if( len > 2048 )
							  	{//网址长度超长
							  		if( (len-UrlLen) < 2048 )//主机域长度合格，只送检主机域
							  		{
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  			len = len-UrlLen;
							  		}
							  		else//主机域长度也超长,取Host域，第一个‘/’前的值
							  		{
							  			int index = 0;
							  			for(; index < len-UrlLen; index++ )
							  			{
							  				if( WaitingFstInfo.pHost[index] == '/' )
							  					break;
							  			}
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, index+1 );
							  			len = index+1;
							  		}
							  	}
							  	else
							  	{//网址不超长
							  		strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  		strncat( pRealUrl, WaitingFstInfo.pUrl, UrlLen );
							  	}
							  }	
							  
							  ExFreePool( WaitingFstInfo.pHost ); 
							  ExFreePool( WaitingFstInfo.pUrl ); 
							  */
							}
							else//分包中包含完整的Host信息
							{		
						  	len = (HttpHost.end_offset-HttpHost.begin_offset+1)+(HttpUrl.end_offset-HttpUrl.begin_offset+1);
							  if( len > 2048 )
							  {
							  	if( HostLen < 2048 )//取主机域
							  	{
							  		HTTP_INFO hp = {0};
							  		GetRealUrl( pRealUrl, HttpHost, hp, 2048, pAppData );
							  		len = HostLen;
							  	}
							  	else//取主机域中第一个'\'前的值
							  	{
							  		int index = 0;
							  		for(; index < HostLen; index++ )
							  		{
							  			if( pAppData[HttpHost.begin_offset+index] == '/' )
							  				break;
							  		}
							  		strncpy( pRealUrl, pAppData+HttpHost.begin_offset, index+1 );
							  		len = index+1;
							  	}
								  
							  }
							  else
							     GetRealUrl( pRealUrl, HttpHost, HttpUrl, 2048, pAppData );
							  
							//提取Refer主网址
							  if( ReferLen > 0 )
							  {
								   int index = HttpReferer.begin_offset+7;
								   for(; index-HttpReferer.begin_offset < ReferLen; index++ )
								   {
									    if( pAppData[index] == '/' )
										     break;
							     }
								   if( index-HttpReferer.begin_offset < ReferLen )
									    ReferMainLen = index - HttpReferer.begin_offset - 7;
								   else
									    ReferMainLen = ReferLen;
								   if( ReferMainLen < 100 )
								      strncpy( pRefer, pAppData+HttpReferer.begin_offset+7, ReferMainLen );
								   else
									    KdPrint(("ReferMainLen > 100\n"));
						  	}
						  }
							
							//将要检测的网址存入pRealUrl,长度为len
		Position:
							KdPrint(("Url：%s\n", pRealUrl ));
							KdPrint(("Refer：%s\n", pRefer));
							//if( strstr( pRealUrl, "www.163.com") != NULL )
							//	return STATUS_DROP; 
							if( urlCnt > 0 )
							{
								//遍历被禁止的url列表
								int r = 0;
								for( r = 0; r < urlCnt; r++ )
								{
									if( strstr( pRealUrl, UrlInfos[r].pUrl ) != NULL )
										return STATUS_DROP;
								} 
							}
							return STATUS_PASS;
							/*
							//做预处理：只要Refer和网址的主网址相同，则直接放过
							if( ReferMainLen != 0 && 0 == strncmp( pRealUrl, pRefer, ReferMainLen ) )
							{
								DbgPrint("host and refer are the same, pass\n");
								return STATUS_PASS;
							}
							else
							{
								//进行第二次预处理,提取网址中的主网址，查找保存的安全主网址，如果存在且在安全时间内
								//则为安全主网址，直接放过，且修改该网址对应的时间值
								BOOLEAN bExist = FALSE;
								int MainRealUrlLen = 0;
								char* position = strchr( pRealUrl, '/' );
								if( position != NULL )
								  MainRealUrlLen = position - pRealUrl + 1;
								else
									MainRealUrlLen = len;
								bExist = ExistMainUrl( pRealUrl, MainRealUrlLen );
								if( bExist == TRUE )
								{
									DbgPrint("host is in the safe urls\n");
									return STATUS_PASS;
								}
									
							}
							*/
					  	//经过两次预处理后，仍然无法确定为安全网页，送往服务器检测
					  	/*
					  	处理方法：
					  	1.无论该包是否被拆分，处理到这里，要检测的网址已存放在pRealUrl中
					  	2.创建命名事件，用于等待应用层的处理结果
					  	3.将必要信息，存放入全局数组DealInfos数组
					  	4.等待应用层的处理结果
					  	5.等待事件被激活后，处理DealInfos、WaitingInfo数据
					  	6.根据检测结果，决定是否放过该包
					  	*/
					  	
							DealInfo.UrlInfo.pUrl = (char*)ExAllocatePool( NonPagedPool, len+1 );
							memset( DealInfo.UrlInfo.pUrl, 0, len+1 );
							
							memcpy( DealInfo.UrlInfo.pUrl, pRealUrl, len );
							DealInfo.UrlInfo.len = len;
							//ExFreePool(pUrlInfo);
							/*
							if( EventIndex >= 300 )
								 EventIndex = 0;
							++EventIndex;
							swprintf( ch, L"\\BaseNamedObjects\\SysEvent%d", EventIndex );
							RtlInitUnicodeString( &EventName, ch );
							
							DbgPrint("%wZ\n", &EventName );
							
							pKEvent = IoCreateSynchronizationEvent( &EventName, &hThread );
							KeClearEvent( pKEvent );
							DealInfo.pKEvent = pKEvent;
							
							DealInfo.bSafe = TRUE;
							DealInfo.bDealing = FALSE;
							
							NdisAcquireSpinLock( &gSpinLock );
							DealInfos[count++] = DealInfo;
							NdisReleaseSpinLock( &gSpinLock );
									
              //延时1000nm
							{
							LARGE_INTEGER LargeTime = {0};
							LargeTime.QuadPart = 1000;
							KeDelayExecutionThread( KernelMode, FALSE, &LargeTime );
						  }
						  
							KeSetEvent( pKEventForDll, 0, FALSE );
							DbgPrint("通知应用层完成\n");
					 
						  DbgPrint("驱动事件等待\n");
							KeWaitForSingleObject( pKEvent, Executive, KernelMode, 0, 0 );
							DbgPrint("驱动中的事件获取通知\n");
							 
							NdisAcquireSpinLock( &gSpinLock );
							for( index = 0; index < count; index++ )
							{
								DbgPrint("驱动层获取检测结果\n");
								if( strcmp( &(DealInfos[index].UrlInfo), &(DealInfo.UrlInfo) ) == 0 )
								{
									DealInfo.bSafe = DealInfos[index].bSafe;
									break;
								}
							}
							//删除已经处理结束的URL
							
							if( index < count )
							{
								if( DealInfos[index].UrlInfo.pUrl == NULL )
									DbgPrint("1111");
								//	NdisAcquireSpinLock( &gSpinLock );
								//ExFreePool( DealInfos[index].UrlInfo.pUrl );
								//DealInfos[index].UrlInfo.pUrl = NULL;
								ExFreePool( DealInfo.UrlInfo.pUrl );
							
								for(; index < count; index++ )
								{
									DbgPrint("驱动层处理等待Url队列\n");
									DealInfos[index] = DealInfos[index+1];
								}
								count--;
								NdisReleaseSpinLock( &gSpinLock );
							}
							else
							{
								for( index = 0; index < count; index++ )
								{
									DbgPrint("驱动层获取检测结果\n");
									if( strcmp( &(DealInfos[index].UrlInfo), &(DealInfo.UrlInfo) ) == 0 )
									{
										DealInfo.bSafe = DealInfos[index].bSafe;
										break;
										}
								}
								DbgPrint("Not Found\n");
							}
							*/
							//再次获得WaitingIndex
							//处理全局分包数据
							/*
							if( state != 0 )
							{
							 	WAITING_INFO WaitingSecInfo = {0};
					     	NdisAcquireSpinLock( &gWaitingSpinLock );
						  	 WaitingIndex = 0;
						  	 if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
					    	 {//正常情况下应该成功
					  	   	 WaitingSecInfo = WaitingInfo[WaitingIndex];
					  	   	 for(; WaitingIndex < WaitingCnt; WaitingIndex++ )
											 WaitingInfo[WaitingIndex] = WaitingInfo[WaitingIndex+1];
									 WaitingCnt--;
					  	  	 NdisReleaseSpinLock( &gWaitingSpinLock );
					  	    
					  	     ExFreePool( WaitingSecInfo.pHost );
					  	     ExFreePool( WaitingSecInfo.pUrl );
					  	     ExFreePool( WaitingSecInfo.pRefer );
					  	
					       }
					       else
					      	NdisReleaseSpinLock( &gWaitingSpinLock );
				   	  }
						
						  if( DealInfo.bSafe )
						  {//服务器检测结束后，如果为安全网页，添加入安全主网页缓存
							  
							  //先从网址中提起主网址，如果该主网址已存在，更新时间后，直接放过
							  BOOLEAN bExist = FALSE;
								int MainRealUrlLen = 0;
								char* position = strchr( pRealUrl, '/' );
								if( position != NULL )
								  MainRealUrlLen = position - pRealUrl + 1;
								else
									MainRealUrlLen = len;
								bExist = ExistMainUrl( pRealUrl, MainRealUrlLen );
								if( bExist == TRUE )
									return STATUS_PASS;
								else
								{
									//该主网址不在安全缓存中，保存该值
									SAFE_URL SafeUrl = {0};
									
									LARGE_INTEGER SysTime = {0};
		              LARGE_INTEGER LocTime = {0};
		              ULONG Seconds = 0;
		              KeQuerySystemTime( &SysTime );
	              	ExSystemTimeToLocalTime( &SysTime, &LocTime );
	              	RtlTimeToSecondsSince1980( &LocTime, &Seconds );
									
									SafeUrl.MainUrlLen = MainRealUrlLen;
									strncpy( SafeUrl.MainUrl, pRealUrl, MainRealUrlLen );
									SafeUrl.Seconds = Seconds;
									
									if( SafeUrlCnt < 500 )
									{//缓冲未满，直接添加
										NdisAcquireSpinLock( &gSafeUrlSpinLock );
										SafeUrls[SafeUrlCnt++] = SafeUrl;
										NdisReleaseSpinLock( &gSafeUrlSpinLock );
									}
									else
									{//缓冲已满，需要替换一个。选择最早访问的那个
										int index = 0;
										int oldest = 0;
										ULONG OldSeconds = 0;
										NdisAcquireSpinLock( &gSafeUrlSpinLock );
										OldSeconds = SafeUrls[index].Seconds;
										index++;
										for(; index < SafeUrlCnt; index++ )
										{
											if( SafeUrls[index].Seconds < OldSeconds )	
											{
												oldest = index;
												OldSeconds = SafeUrls[index].Seconds;
											}
										}
										SafeUrls[oldest] = SafeUrl;
										NdisReleaseSpinLock( &gSafeUrlSpinLock );
									}
									
								}
								return STATUS_PASS;
						  }
						  else
								return STATUS_DROP;
*/
							//NdisReleaseSpinLock( &gSpinLock );
							//DbgPrint("-------------------\n退出自旋锁\n");
							
							
							//ExFreePool( pUrlInfo );
							//pUrlInfo = NULL;
							
							/*
							if(pKEventForDll)
							{
								ObDereferenceObject(pKEventForDll); // delete event reference
								pKEventForDll = NULL;
							}	

							if(pKEventForSys)
							{
								ObDereferenceObject(pKEventForSys); // delete event reference
								pKEventForSys = NULL;
							}	
							*/
							/*
							if( bSafeUrl )
								return STATUS_PASS;
							else
								return STATUS_DROP; 
								*/
							
							
							//
							//return STATUS_DROP;
						}
						//不是请求网页分包
					}
					//DbgPrint("Send TCP packet");
			   
			  }
				break;
			}
		}else if(pPacketContent[12] == 8 &&  pPacketContent[13] == 6 )
		{
			
			if(bRecOrSend)
				KdPrint(("Receive ARP packet"));
			else
				KdPrint(("Send ARP packet"));
			
		}else{
			
			if(bRecOrSend)
				KdPrint(("Receive unknown packet"));
			else
				KdPrint(("Send unknown packet"));
				
		}
                             

	 }
	 __finally
	{
		if( MmIsAddressValid(pPacketContentTmp) )
			NdisFreeMemory(pPacketContentTmp, 0, 0);
	}

	return STATUS_PASS;
}


FILTER_RESULT AnalysisNetBuffer( PNET_BUFFER pNetBuffer, BOOLEAN bRecOrSend )
{
	FILTER_RESULT status = STATUS_PASS; // 默认全部通过
	DWORD dwBufferLen = 0;
	DWORD dwCopyLen = 0;
	PUCHAR pPacketContent = NULL;
	__try{
					dwBufferLen = NET_BUFFER_DATA_LENGTH(pNetBuffer);
					status = NdisAllocateMemoryWithTag( &pPacketContent, dwBufferLen, TAG); 
					if( status != NDIS_STATUS_SUCCESS )
					{
						status = NDIS_STATUS_FAILURE ;
						__leave;
					}
					dwCopyLen = dwBufferLen;
					NdisZeroMemory( pPacketContent, dwBufferLen );
					CopyBytesFromNetBuffer( pNetBuffer, &dwCopyLen, pPacketContent );
					if( dwCopyLen != dwBufferLen )
					{
						status = NDIS_STATUS_FAILURE ;
						__leave;
					}
							// 取得数据包内容后，下面将对其内容进行过滤。
		// 我们在这个函数中的实现，仅仅简单地打印一些可读的Log信息。
		if(pPacketContent[12] == 8 &&  pPacketContent[13] == 0 )  //is ip packet
		{	
			PIP_HEADER pIPHeader = (PIP_HEADER)(pPacketContent + IP_OFFSET);
			switch(pIPHeader->Protocol)
			{
			case PROT_ICMP:
				if(bRecOrSend)
					KdPrint(("Receive ICMP packet"));
				else
					KdPrint(("Send ICMP packet"));

				//
				// 取得ICMP头，做出你的过滤判断。
				// 
				break;
			case PROT_UDP:
				
				if(bRecOrSend)
					KdPrint(("Receive UDP packet"));
				else
					KdPrint(("Send UDP packet"));

				//
				// 取得UDP头，做出你的过滤判断。
				//
				
				break;
			case PROT_TCP:
				if(bRecOrSend)
				{
					KdPrint(("Receive TCP packet"));
					break;
					
				}
				else
				{//send packet
					
					PTCP_HEADER pTcpHeader = (PTCP_HEADER)( (UCHAR*)pIPHeader + ((pIPHeader->VIHL)&0xf)*4 );
					UINT HeaderLen = (((pTcpHeader->LenAndRes)&0x00f0)>>4)*4 + ((pIPHeader->VIHL)&0xf)*4 + 0xe;
				
					
					if( (dwBufferLen > HeaderLen) && (pTcpHeader->DestPort == 0x5000) )
					{//有应用层数据，且应用程的端口号为80
						char *pAppData = pPacketContent + HeaderLen+12;
						UINT AppDataLen = dwBufferLen - HeaderLen-12;
						
						//与应用层交互所需变量
						DEAL_INFO DealInfo = {0};
						PKEVENT pKEvent = NULL;
						UNICODE_STRING EventName;
						WCHAR ch[200];
						HANDLE hThread;
						int index = 0;
						
						//根据数据包SeqNum，判断是否是被等待包
						int WaitingIndex = 0;
						
						//存储提取后的网址
						char pRealUrl[2048] = {0};
						int len = 0;
						
						
						//存储提取后的refer，用于检测过滤
						char pRefer[100] = {0};
						int  ReferMainLen = 0;
						
						
						//网络字节序与主机字节序转换
						pTcpHeader->SeqNum = Myhtonl( pTcpHeader->SeqNum );
						
						NdisAcquireSpinLock( &gWaitingSpinLock );
						if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
						{//是等待分包
							
							int state = WaitingInfo[WaitingIndex].state;

							NdisReleaseSpinLock( &gWaitingSpinLock );
							//不考虑GET命令被分成3个/3个以上包的情况
							{
							
							char* pHost = NULL;
							int   begin = 0;
							int   end   = 0;
							switch( state )
							{
								case 1:
									{//未包含键名
										UINT index = 0;
										begin = 0;
										for(; index < AppDataLen; index++ )
										{
											if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
											{//因为未考虑GET命令3个以上分包，所以必然成功
												end = index;
											  break;
											}
										}
										break;
									}
								case 2:
									{//包含部分键名
										UINT index = 0;
										BOOLEAN bFound = FALSE;
										for(; index < AppDataLen; index++ )
										{
											if( !bFound )
											{
											   if( 0x20  == pAppData[index] )
											   {
												    begin = index+1;
												    bFound = TRUE;
												    continue;
										     }
										  }
											if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
											{
												end = index;
												break;
											}
										}
										break;
									}
								case 3:
									{//包含全部键名
										UINT index = 0;
										BOOLEAN bFound = TRUE;
										
										for(; index < AppDataLen; index++ )
										{
											if( !bFound )
										  {
											   if( 0 == strncmp( pAppData+index, "Host:", 5 ) )
											   {
											     	begin = index+6;
												    index = index+5;
												    continue;
											   }
										  }
										  if( 0 == strncmp( pAppData+index, "\r\n", 2 ) )
										  {
										  	end = index;
										  	break;
										  }	
										}
										break;
									}
									
							}
							//查找到剩余的Host信息的起始位置，未考虑分包数 >= 3情况，必然成立
							if( end > begin )
							{
								//存储剩余的Host信息
								WAITING_INFO WaitingFstInfo = {0};
								int SecHostLen = end - begin;
								pHost = (char*)ExAllocatePool( NonPagedPool, SecHostLen+1 );
								memset( pHost, 0, SecHostLen+1 );
								strncpy( pHost, pAppData+begin, SecHostLen );
								
								//将获取的剩余Host信息与前部分Host信息整合
								NdisAcquireSpinLock( &gWaitingSpinLock );
								//重新获取WaitingIndex
								WaitingIndex = 0;
								if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
								{//必然能找到
	                
									
									//存储完整Host值长度
									UINT HostLen = 0;
									UINT UrlLen = 0;
									UINT FstHostLen = 0;
									
									WaitingFstInfo = WaitingInfo[WaitingIndex];
									HostLen = WaitingFstInfo.HostLen + SecHostLen;
									UrlLen = WaitingFstInfo.UrlLen;
									FstHostLen = WaitingFstInfo.HostLen;
	                if( HostLen > 2048 )
	                {
	                	HostLen = 2048;
	                }
	                
	
	                WaitingInfo[WaitingIndex].HostLen = HostLen; 
									NdisReleaseSpinLock( &gWaitingSpinLock );
									
	                //整合Host值
	                strncat( WaitingFstInfo.pHost+FstHostLen, pHost, HostLen-FstHostLen );
	                ExFreePool( pHost );
	                pHost = NULL;
	                
	                
	                //对整合后的Host做简要处理，如果是我们自己构建的检测包，直接放过
	                if( HostLen > strlen("reputation.cloudsvc.net") )
	                {
	                	if( 0 == strncmp( WaitingFstInfo.pHost, "reputation.cloudsvc.net", strlen("reputation.cloudsvc.net") ) )
	                	{//此种情况，只会出现在我们的检测包的Host值，被拆分
	                		ExFreePool( WaitingFstInfo.pHost );
					  	        ExFreePool( WaitingFstInfo.pUrl );
					  	        ExFreePool( WaitingFstInfo.pRefer );
	                		
							        return STATUS_PASS;
							      }
	                }
	                //整合网址，并存放入pRealUrl
	                len = HostLen + WaitingFstInfo.UrlLen;
							  	if( len > 2048 )
							  	{//网址长度超长
							  		if( (len-UrlLen) < 2048 )//主机域长度合格，只送检主机域
							  		{
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  			len = len-UrlLen;
							  		}
							  		else//主机域长度也超长,取Host域，第一个‘/’前的值
							  		{
							  			UINT index = 0;
							  			for(; index < len-UrlLen; index++ )
							  			{
							  				if( WaitingFstInfo.pHost[index] == '/' )
							  					break;
							  			}
							  			strncpy( pRealUrl, WaitingFstInfo.pHost, index+1 );
							  			len = index+1;
							  		}
							  	}
							  	else
							  	{//网址不超长
							  		strncpy( pRealUrl, WaitingFstInfo.pHost, len-UrlLen );
							  		strncat( pRealUrl, WaitingFstInfo.pUrl, UrlLen );
							  	}
							  	//提取Refer主网址
							  	if( WaitingFstInfo.ReferLen > 0 )
							  	{
							  		//Refer:http://xxx.xxx,前面有7个无用符号
							  		UINT index = 7;
							  		for(; index < WaitingFstInfo.ReferLen; index++ )
							  		{
							  			if( WaitingFstInfo.pRefer[index] == '/' )
							  				break;
							  		}
							  		if( index < WaitingFstInfo.ReferLen )
							  			ReferMainLen = index-7;
							  		else
							  			ReferMainLen = WaitingFstInfo.ReferLen;
							  		if( ReferMainLen < 100 )
							  		  strncpy( pRefer, WaitingFstInfo.pRefer+7, ReferMainLen );
							  		else
							  			DbgPrint("ReferMainLen > 100\n");
							  	}
									goto Position;
									
						    }
						  }
							
						  }
						}
						else
						   NdisReleaseSpinLock( &gWaitingSpinLock );
						
						//不是被等待分包,判断是否为Get请求包
						if( IsHttpGetMethod(pAppData, AppDataLen ) )
						{//client请求网页

							HTTP_INFO HttpUrl = {0};
							HTTP_INFO HttpVersion = {0};
							HTTP_INFO HttpReferer = {0};
							HTTP_INFO HttpHost = {0};
							

							
							UINT HostLen = 0;
							UINT UrlLen = 0;
							UINT ReferLen = 0;
							
							
							//标识该分包能否提取出完成的"键名"+键值,0:完整；1:"键名"完整，键值不完整；2："键名"不完整；3：无
							UINT state = 0;
							
							//获取Url信息值
							HttpUrl = GetHttpGetMethodUrl( pAppData, AppDataLen );
						  //判断改包是否符合HTTP协议格式
						  if( HttpUrl.end_offset < HttpUrl.begin_offset )
							{//Url超长或不存在Url
								 return STATUS_DROP;
							}
							
							//获取HTTP版本值
							HttpVersion = GetHttpVersion( pAppData, HttpUrl, AppDataLen );
							if( HttpVersion.end_offset < HttpUrl.begin_offset )
								return STATUS_DROP;
							
							HttpReferer = GetHttpSubKey( pAppData, HttpVersion, "Referer:", AppDataLen, &state );
							HttpHost = GetHttpSubKey( pAppData, HttpVersion, "Host:", AppDataLen, &state );
							
							//提取待检验的网址
							if( HttpHost.end_offset == 0 )
								HostLen = 0;
							else
							{
							  HostLen = (HttpHost.end_offset - HttpHost.begin_offset+1);
							  HostLen = HostLen < 2048 ? HostLen: 2048;
							}
							if( HttpUrl.end_offset == 0 )
								UrlLen = 0;
							else
							{
							  UrlLen = HttpUrl.end_offset-HttpUrl.begin_offset+1;
							  UrlLen = UrlLen < 2048 ? UrlLen : 2048;
							}
							if( HttpReferer.end_offset == 0 )
								ReferLen = 0;
							else
							{
								ReferLen = HttpReferer.end_offset - HttpReferer.begin_offset+1;
								ReferLen = ReferLen < 2048 ? ReferLen : 2048;
							}
								
							//如果是我们构造的分包，直接放过
							if( HostLen > 0 )
							{
								UINT StrLen = strlen("reputation.cloudsvc.net");
								UINT CmpLen = (StrLen > HostLen ? HostLen:StrLen);
								if( 0 == strncmp( pAppData+HttpHost.begin_offset, "reputation.cloudsvc.net", CmpLen ) )
							        return STATUS_PASS;
							  
							}
							
						
							//如果分包中不包含完整的Host信息
							if( state != 0 )
							{
								//初始化该分包信息
								WAITING_INFO WaitingFstInfo = {0};
								
								//return STATUS_PASS;
								
								WaitingFstInfo.pHost = (char*)ExAllocatePool( NonPagedPool, 2048 );
								memset( WaitingFstInfo.pHost, 0, 2048 );
								if( HostLen > 0 )
								{
									memcpy( WaitingFstInfo.pHost, pAppData+HttpHost.begin_offset, HostLen );
									WaitingFstInfo.HostLen = HostLen;
								}
								
								WaitingFstInfo.pUrl = (char*)ExAllocatePool( NonPagedPool, 2048 );
								memset( WaitingFstInfo.pUrl, 0, 2048 );
								if( UrlLen > 0 )
								{
									memcpy( WaitingFstInfo.pUrl, pAppData+HttpUrl.begin_offset, UrlLen );
									WaitingFstInfo.UrlLen = UrlLen;
							  }
							  
							  WaitingFstInfo.pRefer = (char*)ExAllocatePool( NonPagedPool, 2048 );
							  memset( WaitingFstInfo.pRefer, 0, 2048 );
							  if( ReferLen > 0 )
							  {
							  	memcpy( WaitingFstInfo.pRefer, pAppData+HttpReferer.begin_offset, ReferLen );
							  	WaitingFstInfo.ReferLen = ReferLen;
							  }
							  
							  WaitingFstInfo.SeqNum = pTcpHeader->SeqNum + AppDataLen;
							  if( (pTcpHeader->LenAndRes)&0x0300 )
							  	WaitingFstInfo.SeqNum++;
							  WaitingFstInfo.state = state;

							  
							  //存储该分包信息
							  NdisAcquireSpinLock( &gWaitingSpinLock );
							  WaitingInfo[WaitingCnt++] = WaitingFstInfo;
							  NdisReleaseSpinLock( &gWaitingSpinLock );
							  
							  return STATUS_PASS;
							  
							}
							else//分包中包含完整的Host信息
							{		
						  	len = (HttpHost.end_offset-HttpHost.begin_offset+1)+(HttpUrl.end_offset-HttpUrl.begin_offset+1);
							  if( len > 2048 )
							  {
							  	if( HostLen < 2048 )//取主机域
							  	{
							  		HTTP_INFO hp = {0};
							  		GetRealUrl( pRealUrl, HttpHost, hp, 2048, pAppData );
							  		len = HostLen;
							  	}
							  	else//取主机域中第一个'\'前的值
							  	{
							  		UINT index = 0;
							  		for(; index < HostLen; index++ )
							  		{
							  			if( pAppData[HttpHost.begin_offset+index] == '/' )
							  				break;
							  		}
							  		strncpy( pRealUrl, pAppData+HttpHost.begin_offset, index+1 );
							  		len = index+1;
							  	}
								  
							  }
							  else
							     GetRealUrl( pRealUrl, HttpHost, HttpUrl, 2048, pAppData );
							  
							//提取Refer主网址
							  if( ReferLen > 0 )
							  {
								   UINT index = HttpReferer.begin_offset+7;
								   for(; index-HttpReferer.begin_offset < ReferLen; index++ )
								   {
									    if( pAppData[index] == '/' )
										     break;
							     }
								   if( index-HttpReferer.begin_offset < ReferLen )
									    ReferMainLen = index - HttpReferer.begin_offset - 7;
								   else
									    ReferMainLen = ReferLen;
								   if( ReferMainLen < 100 )
								      strncpy( pRefer, pAppData+HttpReferer.begin_offset+7, ReferMainLen );
								   else
									    DbgPrint("ReferMainLen > 100\n");
						  	}
						  }
							
							//将要检测的网址存入pRealUrl,长度为len
		Position:
							DbgPrint("Url：%s\n", pRealUrl );
							DbgPrint("Refer：%s\n", pRefer);
							//if( strstr( pRealUrl, "www.163.com") != NULL )
							if( dw_win7UrlCnt > 0 )
							{
								//遍历被禁止的url列表
								UINT r = 0;
								for( r = 0; r < dw_win7UrlCnt; r++ )
								{
									if( strstr( pRealUrl, psz_win7DangeUrl[r] ) != NULL )
										return STATUS_DROP;
								} 
							}
							else
							{
								//篡改数据包
								
							}
							return STATUS_PASS;
						}
						//不是请求网页分包
					}
					//DbgPrint("Send TCP packet");
			   
			  }
				break;
			}
		}else if(pPacketContent[12] == 8 &&  pPacketContent[13] == 6 )
		{
			
			if(bRecOrSend)
				DbgPrint("Receive ARP packet");
			else
				DbgPrint("Send ARP packet");
			
		}else{
			
			if(bRecOrSend)
				DbgPrint("Receive unknown packet");
			else
				DbgPrint("Send unknown packet");
				
		}
	}__finally
	{
		if(pPacketContent)
			NdisFreeMemory(pPacketContent, 0, 0);
	}
	return STATUS_PASS;
}



void CopyBytesFromNetBuffer( PNET_BUFFER NetBuffer, PDWORD cbDest, PVOID Dest )
{
	NDIS_STATUS Status = NDIS_STATUS_SUCCESS;
	PMDL CurrentMdl = NET_BUFFER_CURRENT_MDL(NetBuffer);
	DWORD DestOffset = 0;
	while( ( DestOffset < *cbDest ) && CurrentMdl )
	{
		PUCHAR SrcMemory = MmGetSystemAddressForMdlSafe(CurrentMdl,LowPagePriority);
		ULONG Length = MmGetMdlByteCount(CurrentMdl);
		if( !SrcMemory )
		{
			Status = NDIS_STATUS_RESOURCES;
			break;
		}
		if( DestOffset == 0 )
		{
			ULONG MdlOffset = NET_BUFFER_CURRENT_MDL_OFFSET(NetBuffer);
			SrcMemory += MdlOffset;
			Length = MdlOffset;
		}
		Length = Length < (*cbDest-DestOffset)?Length:(*cbDest-DestOffset);
		NdisMoveMemory( (PUCHAR)Dest+DestOffset, SrcMemory, Length );
		DestOffset += Length;
		
		CurrentMdl = NDIS_MDL_LINKAGE(CurrentMdl);
	}
	
	if( Status == NDIS_STATUS_SUCCESS )
		*cbDest = DestOffset;
	return;
}

BOOLEAN IsHttpGetMethod( char* pAppData, int AppDataLen  )
{
	if( AppDataLen < 3 )
		return FALSE;
	if( (*pAppData == 'G') && (*(pAppData+1) == 'E') && (*(pAppData+2) == 'T') )
		return TRUE;

	return FALSE;
}

HTTP_INFO GetHttpGetMethodUrl( char* pAppData, int AppDataLen )
{
	HTTP_INFO HttpUrl = {0};
	int len = 0;
	
	HttpUrl.begin_offset = 4;
	pAppData += HttpUrl.begin_offset;
	while( *pAppData != 0x20 )
	{
		len++;
		pAppData++;
		if( (HttpUrl.begin_offset+len) > AppDataLen )
		{//基本不会出现这种情况，即Url已经超过包的最大长度,不做处理
			len = 0;
			break;
		}
	}
	HttpUrl.end_offset = HttpUrl.begin_offset + len -1;
	return HttpUrl;
}

HTTP_INFO GetHttpVersion( char* pAppData, HTTP_INFO HttpUrl, int AppDataLen )
{
	HTTP_INFO HttpVersion = {0};
	int len = 0;

	HttpVersion.begin_offset = HttpUrl.end_offset + 0x2;
	while( pAppData[HttpVersion.begin_offset] != 0xd || pAppData[HttpVersion.begin_offset+1] != 0xa )
	{
		len++;
		pAppData++;
		if( (HttpVersion.begin_offset+len) > AppDataLen )
		{//基本不会出现这种情况，即Url已经超过包的最大长度,不做处理
			len = 0;
			break;
		}
	}
	
	HttpVersion.end_offset = HttpVersion.begin_offset + len -1;

	return HttpVersion;
	
}

HTTP_INFO GetHttpSubKey( char* pAppData, HTTP_INFO HttpVersion, char* pSubKey, int AppDataLen, int* state )
{
	HTTP_INFO HttpInfo = {0};
	int begin = HttpVersion.end_offset + 0x3;
	int len = 0;

	
	if( IsFindSubKey(pAppData, &begin, pSubKey, AppDataLen) )
	{//包含完整键名
		int SubKeyLen = strlen(pSubKey);
		int StartPosition = begin + SubKeyLen + 1;
		int EndPosition = StartPosition;
		BOOLEAN bOver = FALSE;
		
		while( EndPosition < AppDataLen )
		{
			if( 0 == strncmp( pAppData+EndPosition, "\r", 1 ) )
			{
				bOver = TRUE;
				break;
			}
			EndPosition++;
		}
		if( bOver == TRUE )
		{//找到完整的键值,分两种情况：1.包含"\n\r";2.包含"\n"
			*state = 0;
		}
		else if( EndPosition != StartPosition )
		{//无完整键值,但该包，包含部分键值
			*state = 1;
		}
		else
		{//区分该包是否包含"Host:"后的空格,此时该包以不含任何键值
			if( StartPosition-1 == AppDataLen )//空格不在该包
				*state = 2;
			else//空格在该包中
				*state = 1;
			return HttpInfo;		
		}
		
		HttpInfo.begin_offset = StartPosition;
	  HttpInfo.end_offset = EndPosition-1;
	  return HttpInfo;
	}
	else //分两种情况,1.包完整，2.包不完整
	{
		UINT StartPosition = AppDataLen - 1;
		BOOLEAN bFound = FALSE;
		if( 0 == strncmp( pAppData+AppDataLen-0x4, "\r\n\r\n", 4 ) )
		{
			*state = 0;
			return HttpInfo;
		}
		//未包含键名，分两种情况：例如“Host:”,1.完全不包含；2.包含部分
    if( pAppData[StartPosition] == '\r' || pAppData[StartPosition] == '\n' )
    {
    	*state = 3;
    	return HttpInfo;
    }
		for(; StartPosition > 0; StartPosition-- )
		{
			if( pAppData[StartPosition-1] == '\r' && pAppData[StartPosition] == '\n' )
			{
				bFound = TRUE;
				break;
			}
		}
		if( bFound )
		{//必然能找到，倒数第一个"\n\r"
			if( (UINT)((AppDataLen - StartPosition)) < strlen(pSubKey) && 0 == strncmp( pSubKey, pAppData+StartPosition+1, AppDataLen - StartPosition ) )
				*state = 2;
			else
				*state = 3;
		}
		return HttpInfo;
	}
	
	return HttpInfo;
}

BOOLEAN IsFindSubKey( char* pAppData, int* begin, char* pSubKey, int AppDataLen )
{
	BOOLEAN bFind = FALSE;
	int SubKeyLen = strlen(pSubKey);
	int TempPosition = *begin;
	while( TempPosition < AppDataLen-SubKeyLen )
	{
		int index = 0;
		for(; index < SubKeyLen; index++ )
		{
			if( pAppData[TempPosition+index] != pSubKey[index] )
				break;
		}

		if( index == SubKeyLen )
		{
			bFind = TRUE;
			*begin = TempPosition;
			break;
		}
		else
		{
			TempPosition++;
		}
	}
	return bFind;

}

void GetRealUrl( char* pRealUrl, HTTP_INFO pHost, HTTP_INFO pUrl, int len, char* pAppData )
{
	int index = 0;
	

	   while( pHost.begin_offset < pHost.end_offset+1 )
	   {
		    pRealUrl[index++] = pAppData[pHost.begin_offset++];
		    if( index > len-1 )
			  break;
	   }
 

 
  
	   while( pUrl.begin_offset < pUrl.end_offset+1 && pUrl.begin_offset)
	   {
		    pRealUrl[index++] = pAppData[pUrl.begin_offset++];
		    if( index > len-1 )
		  	break;
	   }
  

}


BOOLEAN IsWaitingPacket( ULONG SeqNum, int* WaitingIndex )
{
	if( WaitingCnt == 0 )
		return FALSE;
	else
	{
		int index = 0;
		for( ; index < WaitingCnt; index++ )
		{
			if( WaitingInfo[index].SeqNum == SeqNum )
			{
				*WaitingIndex = index;
				return TRUE;
			}
		}
		return FALSE;
		
	}
	
}

ULONG Myhtonl( ULONG hSeqNum )
{
	int index = 0;
	ULONG nSeqNum = 0;
	int size = sizeof( hSeqNum );
	char* pNSeqNum = (char*)&nSeqNum;
	char* pHSeqNum = (char*)&hSeqNum;
	for(; index < size; index++ )
	{
		*(pNSeqNum+size-1-index) = *(pHSeqNum+index);
	}
	return nSeqNum;
}

/*
功能：判断pMainUrl所指向的主网址，是否是已检测过的安全网址，若检测过，更新时间值，返回true；不是直接返回false
*/
/*
BOOLEAN ExistMainUrl( char* pMainUrl, int MainUrlLen )
{
	int index = 0;
	BOOLEAN bExist = FALSE;
	SAFE_URL SafeUrl = {0};
	
	ASSERT( MainUrlLen < 100 );
	ASSERT( pMainUrl != NULL );
	
	NdisAcquireSpinLock( &gSafeUrlSpinLock );
	for(; index < SafeUrlCnt; index++ )
	{
		if( 0 == strncmp( SafeUrls[index].MainUrl, pMainUrl, MainUrlLen ) )
		{
			SafeUrl = SafeUrls[index];
			bExist = TRUE;
			break;
		}
	}
	NdisReleaseSpinLock( &gSafeUrlSpinLock );
	if( bExist )
	{
		LARGE_INTEGER SysTime = {0};
		LARGE_INTEGER LocTime = {0};
		ULONG Seconds = 0;
		KeQuerySystemTime( &SysTime );
		ExSystemTimeToLocalTime( &SysTime, &LocTime );
		RtlTimeToSecondsSince1980( &LocTime, &Seconds );
		if( Seconds - SafeUrl.Seconds > 28800 )//8*60*60 == 28800
		{//超过8小时，直接返回false
			return FALSE;		
		}
		else
		{//小于8小时，安全网页，更新最后访问时间
			index = 0;
			NdisAcquireSpinLock( &gSafeUrlSpinLock );
			for(; index < SafeUrlCnt; index++ )
			{
				if( 0 == strncmp( SafeUrls[index].MainUrl, pMainUrl, MainUrlLen ) )
				{
					if( SafeUrls[index].Seconds < Seconds )
						SafeUrls[index].Seconds = Seconds;
					break;
				}
			}
			NdisReleaseSpinLock( &gSafeUrlSpinLock );
			return TRUE;
		}
		
	}
	else
		return FALSE;
	
}
*/

FILTER_RESULT NeedDealPacket( PNDIS_PACKET Packet )
{
	      //存储数据包内容
        PUCHAR pPacketContent = NULL;
        FILTER_RESULT Status = STATUS_PASS;
        
        //分析数据包时所需变量
        UINT PhysicalBufferCount = 0;//内存中的物理块数
        UINT BufferCount = 0;//该数据包中的NDIS_BUFFER包数
        PNDIS_BUFFER pNdisBuffer = NULL;//指向一个NDIS_BUFFER包
        UINT TotalPacketLength = 0; //数据包中的总长度
        UINT DataOffset = 0;
        
		    KIRQL kIrql;
		    kIrql = KeGetCurrentIrql();
		     Status = NdisAllocateMemoryWithTag( &pPacketContent, 2048, TAG );
        if( Status != NDIS_STATUS_SUCCESS )
        {
        	Status = NDIS_STATUS_FAILURE;
        	return Status;
        }
        NdisZeroMemory( pPacketContent, 2048 );
        
        //分析数据包：首先获取第一个NDIS_BUFFER包，然后利用NdisGetNextBuffer枚举所有的包
        NdisQueryPacket( Packet, &PhysicalBufferCount, &BufferCount, &pNdisBuffer, &TotalPacketLength );
        while( TRUE )
        {
        	//获取Ndis_Buffer中虚拟缓冲的地址
        	PUCHAR tempBuff = NULL;
        	UINT copysize = 0;
        	NdisQueryBufferSafe( pNdisBuffer, &tempBuff, &copysize, NormalPagePriority );
        	if( tempBuff != NULL )
        	{
        		NdisMoveMemory( pPacketContent + DataOffset, tempBuff, copysize );
        		DataOffset += copysize;
        	}
        	//获取下一个Ndis_Buffer数据包
        	NdisGetNextBuffer( pNdisBuffer, &pNdisBuffer );
          if( pNdisBuffer == NULL )
          	break;
        }
        //数据包的内容已经存在于pPacketContent,长度为TotalPacketLength
        
        //判断是否为TCP包，且要求端口为80
        if( pPacketContent[12] == 8 && pPacketContent[13] == 0 )//判断是否是IP包
        {
        	PIP_HEADER pIPHeader = (PIP_HEADER)( pPacketContent + IP_OFFSET );
        	if( pIPHeader->Protocol == PROT_TCP )//判断是否是TCP
        	{
        		//判断端口是否为80，且有无包内容
        		//TCP包头
        		PTCP_HEADER pTcpHeader = (PTCP_HEADER)( (UCHAR*)pIPHeader + ((pIPHeader->VIHL)&0xf)*4 );
        		//包头长度
					  int HeaderLen = (((pTcpHeader->LenAndRes)&0x00f0)>>4)*4 + ((pIPHeader->VIHL)&0xf)*4 + 0xe;
        		if( (DataOffset > (UINT)HeaderLen) && (pTcpHeader->DestPort == 0x5000) )
        		{//有应用层数据，且应用程的端口号为80
        			char *pAppData = pPacketContent + HeaderLen;
						  int AppDataLen = DataOffset - HeaderLen;
						  
						  //首先根据SeqNum判断是否被等待分包
						  int WaitingIndex = 0;
						  //将包SeqNum进程主机字节序和网络字节序转换
						  pTcpHeader->SeqNum = Myhtonl( pTcpHeader->SeqNum );
						  //由于要访问全局数组，利用自旋锁进行同步
						  NdisAcquireSpinLock( &gWaitingSpinLock );
					  	if( IsWaitingPacket(pTcpHeader->SeqNum, &WaitingIndex) )
					  	{//是等待分包
              
                //如果IRQL == DISPACH_LEVEL，直接丢弃
		            if( kIrql == DISPATCH_LEVEL )
		            {
		          	NdisReleaseSpinLock( &gWaitingSpinLock );
		          	NdisFreeMemory( pPacketContent, 0 , 0 );
		          	return STATUS_DROP;
		            }
		            else
		            {
							   NdisReleaseSpinLock( &gWaitingSpinLock );
							   NdisFreeMemory( pPacketContent, 0 , 0 );
							   return STATUS_NEEDDEAL;
					   	  }
					  	}
						  else
						  {//不是被等待包
						     NdisReleaseSpinLock( &gWaitingSpinLock );
						     //判断是否是Get包,若不是，直接放过
						     if( IsHttpGetMethod(pAppData, AppDataLen ) )
						     {//client请求网页
							

							    //如果IRQL == DISPACH_LEVEL,直接丢弃
							    if( kIrql == DISPATCH_LEVEL )
							    {
							    	NdisFreeMemory( pPacketContent, 0, 0 );
							      return STATUS_DROP;
							    }
							    else
							    {
							    	NdisFreeMemory( pPacketContent, 0, 0 );
							    	return STATUS_NEEDDEAL;
							    }
								   			   
						     }
						     else
						     {
						      	NdisFreeMemory( pPacketContent, 0, 0 );
						    	  return STATUS_PASS;
						     }
        		  }
        		}
        		else
        		{//端口不为80，或者无包内容，直接放过
        			NdisFreeMemory( pPacketContent, 0, 0 );
        			return STATUS_PASS;
        		}
        	}
        	else
        	{//是IP包，但非TCP包；直接放过
        		NdisFreeMemory( pPacketContent, 0, 0 );
        		return STATUS_PASS;
        	}
        }
        else
        {//非IP包，直接放过
        	NdisFreeMemory(pPacketContent, 0, 0);
        	return STATUS_PASS;
        }
        
}