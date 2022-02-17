#ifndef __MYCMS_SYSTEM_DRIVER_CORE_H
#define __MYCMS_SYSTEM_DRIVER_CORE_H

#ifdef _WIN32
#include <windows.h>
#define RTLD_NOW 0
#define RTLD_LOCAL 0
#endif

#include <stdlib.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <mycms/mycms-system.h>

#ifdef __cplusplus
extern "C" {
#endif

/* MYCMS_SYSTEM_DRIVER_ID_<group>_<name> MSB_32bit(sha1(<group>_<name>)) */
#define MYCMS_SYSTEM_DRIVER_ID_core_explicit_bzero 0xf6ac4e65
#define MYCMS_SYSTEM_DRIVER_ID_core_free 0x4e483569
#define MYCMS_SYSTEM_DRIVER_ID_core_realloc 0xc4a51b02
#define MYCMS_SYSTEM_DRIVER_ID_core_dlclose 0xbb14c6ec
#define MYCMS_SYSTEM_DRIVER_ID_core_dlopen 0x1b328d93
#define MYCMS_SYSTEM_DRIVER_ID_core_dlsym 0xe37d4adf

#pragma GCC diagnostic ignored "-Wcast-function-type"
MYCMS_SYSTEM_DRIVER_FUNC(core, void, explicit_bzero, void * const s, size_t size)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, realloc, const char * const hint, void * const p, size_t size)
MYCMS_SYSTEM_DRIVER_FUNC(core, bool, free, const char * const hint, void * const p)
MYCMS_SYSTEM_DRIVER_FUNC(core, int, dlclose, void *handle)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, dlopen, const char *filename, int flags)
MYCMS_SYSTEM_DRIVER_FUNC(core, void *, dlsym, void *handle, const char *symbol)
#pragma GCC diagnostic pop

#ifdef __cplusplus
}
#endif

#endif
