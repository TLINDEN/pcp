#ifndef _HAVE_PCP
#define _HAVE_PCP

#ifdef __cplusplus
extern "C" {
#endif

#if defined __linux__ || defined __GNU__ || defined __GLIBC__
#  ifndef _DEFAULT_SOURCE
#    define _DEFAULT_SOURCE 1
#  endif
#
#  ifndef _XOPEN_SOURCE
#    define _XOPEN_SOURCE 1
#  endif
#
#  ifndef _GNU_SOURCE
#    define _GNU_SOURCE 1
#  endif
#else
#  define _BSD_SOURCE 1
#endif

#include "pcp/config.h"
#include "pcp/base85.h"
#include "pcp/buffer.h"
#include "pcp/context.h"
#include "pcp/crypto.h"
#include "pcp/defines.h"
#include "pcp/digital_crc32.h"
#include "pcp/ed.h"
#include "pcp/getpass.h"
#include "pcp/jenhash.h"
#include "pcp/key.h"
#include "pcp/keyhash.h"
#include "pcp/keysig.h"
#include "pcp/mac.h"
#include "pcp/mem.h"
#include "pcp/mgmt.h"
#include "pcp/pad.h"
#include "pcp/pcpstream.h"
#include "pcp/platform.h"
#include "pcp/plist.h"
#include "pcp/randomart.h"
#include "pcp/scrypt.h"
#include "pcp/structs.h"
#include "pcp/uthash.h"
#include "pcp/util.h"
#include "pcp/vault.h"
#include "pcp/version.h"
#include "pcp/z85.h"
#include "pcp/zmq_z85.h"
#ifdef __cplusplus
}
#endif


#endif
