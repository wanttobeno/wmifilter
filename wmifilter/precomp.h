#ifndef _precomp_
#define _precomp_


#pragma warning(disable:4214)   // bit field types other than int

#pragma warning(disable:4201)   // nameless struct/union
#pragma warning(disable:4115)   // named type definition in parentheses
#pragma warning(disable:4127)   // conditional expression is constant
#pragma warning(disable:4054)   // cast of function pointer to PVOID
#pragma warning(disable:4244)   // conversion from 'int' to 'BOOLEAN', possible loss of data
#define NDIS_LEGACY_MINIPORT 1
#define NDIS_SUPPORT_NDIS6 1
#include <ntifs.h>
#include <ndis.h>
#include <windef.h>

#include "ndishk.h"



#endif