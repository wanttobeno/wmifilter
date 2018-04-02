///////////////////////////////////////////////////////////////////////////////
///
/// Copyright (c) 2010 - <company name here>
///
/// Original filename: TdiClient.h
/// Project          : TdiClient
/// Date of creation : <see TdiClient.c>
/// Author(s)        : <see TdiClient.c>
///
/// Purpose          : <see TdiClient.c>
///
/// Revisions:         <see TdiClient.c>
///
///////////////////////////////////////////////////////////////////////////////

// $Id$

#ifndef __TDICLIENT_H_VERSION__
#define __TDICLIENT_H_VERSION__ 100

#if defined(_MSC_VER) && (_MSC_VER >= 1020)
#pragma once
#endif

VOID TdiCommunicateTest();
void GetResponesUrl( char *respones );
void DecodeUrl( char *data );
void DecodeStartType( char *data );
extern BOOLEAN bHttpOk;
//#include "drvcommon.h"
//#include "drvversion.h"

//#define DEVICE_NAME			"\\Device\\TDICLIENT_DeviceName"
//#define SYMLINK_NAME		"\\DosDevices\\TDICLIENT_DeviceName"
//PRESET_UNICODE_STRING(usDeviceName, DEVICE_NAME);
//PRESET_UNICODE_STRING(usSymlinkName, SYMLINK_NAME);

//#ifndef FILE_DEVICE_TDICLIENT
//#define FILE_DEVICE_TDICLIENT 0x800
//#endif

// Values defined for "Method"
// METHOD_BUFFERED
// METHOD_IN_DIRECT
// METHOD_OUT_DIRECT
// METHOD_NEITHER
// 
// Values defined for "Access"
// FILE_ANY_ACCESS
// FILE_READ_ACCESS
// FILE_WRITE_ACCESS

//#define IOCTL_TDICLIENT_OPERATION CTL_CODE(FILE_DEVICE_TDICLIENT, 0x01, METHOD_BUFFERED, FILE_READ_DATA | FILE_WRITE_DATA)

#endif // __TDICLIENT_H_VERSION__
