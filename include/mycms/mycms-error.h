#ifndef __MYCMS_ERROR_H
#define __MYCMS_ERROR_H

#include "mycms-variant.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MYCMS_ERROR_CODE_SUCCESS		0x00000000
#define MYCMS_ERROR_CODE_FAILED			0x00000001
#define MYCMS_ERROR_CODE_MEMORY			0x00000002
#define MYCMS_ERROR_CODE_NO_CONTEXT		0x00000003
#define MYCMS_ERROR_CODE_RELEASE		0x00000004
#define MYCMS_ERROR_CODE_ARGS			0x00000005
#define MYCMS_ERROR_CODE_IO			0x00000006
#define MYCMS_ERROR_CODE_STATE			0x00000007
#define MYCMS_ERROR_CODE_RESOURCE_ACCESS	0x00000008
#define MYCMS_ERROR_CODE_DEPENDENCY		0x00000009
#define MYCMS_ERROR_CODE_NOT_IMPLEMENTED	0x0000000A

#define MYCMS_ERROR_CODE_INTEGRITY_SIZE		0x00100001
#define MYCMS_ERROR_CODE_INTEGRITY		0x00100002
#define MYCMS_ERROR_CODE_NO_KEY			0x00100003
#define MYCMS_ERROR_CODE_CRYPTO			0x00100004

#define MYCMS_ERROR_CODE_USER_BASE		0x80000000

#define MYCMS_ERROR_KEY_AUTHORITATIVE		0x00000000
#define MYCMS_ERROR_KEY_CODE			0x00000001
#define MYCMS_ERROR_KEY_SOURCE_FILE		0x00000002
#define MYCMS_ERROR_KEY_SOURCE_LINE		0x00000003
#define MYCMS_ERROR_KEY_SOURCE_FUNC		0x00000004
#define MYCMS_ERROR_KEY_HINT			0x00000005
#define MYCMS_ERROR_KEY_DESCRIPTION		0x00000006
#define MYCMS_ERROR_KEY_RESOURCE_SIZE		0x00000007
#define MYCMS_ERROR_KEY_RESOURCE_NAME		0x00000008

#define MYCMS_ERROR_KEY_ERRNO			0x00010001
#define MYCMS_ERROR_KEY_ERRNO_STR		0x00010002
#define MYCMS_ERROR_KEY_NTSTATUS		0x00010003
#define MYCMS_ERROR_KEY_OPENSSL_STATUS		0x00010006
#define MYCMS_ERROR_KEY_OPENSSL_STATUS_STR	0x00010007
#define MYCMS_ERROR_KEY_PKCS11_RV		0x00010008
#define MYCMS_ERROR_KEY_PKCS11_RV_STR		0x00010009

#define MYCMS_ERROR_KEY_USER_BASE		0x80000000

typedef struct mycms_error_desc_s {
	uint32_t key;
	char *desc;
	char *format;
} *mycms_error_desc;

typedef struct mycms_error_prm_s {
	uint32_t k;
	mycms_variant *v;
} *mycms_error_prm;

struct __mycms_error_s;
typedef struct __mycms_error_s *mycms_error;
struct __mycms_error_entry_s;
typedef struct __mycms_error_entry_s *mycms_error_entry;

/* TODO: consider property interface */
mycms_error_desc
mycms_error_get_key_desc(
	const uint32_t key
);

bool
mycms_error_has_error(
	const mycms_error error
);

void
mycms_error_reset(
	const mycms_error error
);

bool
mycms_error_format_callback(
	const mycms_error error,
	void (*f)(
		const mycms_error error,
		const unsigned index,
		const mycms_error_prm prms,
		const unsigned prms_len,
		void *d
	),
	void *p
);

bool
mycms_error_format_simple(
	const mycms_error error,
	uint32_t * const code,
	char * const buf,
	const size_t buf_size
);

void
mycms_error_format(
	const mycms_error error,
	char * const buf,
	const size_t buf_size
);

#ifdef __cplusplus
}
#endif

#endif
