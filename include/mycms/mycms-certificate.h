#ifndef __MYCMS_CERTIFICATE_H
#define __MYCMS_CERTIFICATE_H

#include <stdlib.h>

#include "mycms-blob.h"
#include "mycms-context.h"
#include "mycms-dict.h"

#define MYCMS_PRIVATE_OP_ENCRYPT 0
#define MYCMS_PRIVATE_OP_DECRYPT 1

#define MYCMS_PADDING_INVALID -1
#define MYCMS_PADDING_NONE 0
#define MYCMS_PADDING_PKCS1 1
#define MYCMS_PADDING_OEAP 2

struct mycms_certificate_s;
typedef struct mycms_certificate_s *mycms_certificate;

typedef bool (*mycms_certificate_driver_free)(
	const mycms_certificate certificate
);

typedef bool (*mycms_certificate_driver_load)(
	const mycms_certificate certificate,
	const mycms_dict dict
);

typedef int (*mycms_certificate_driver_rsa_private_op)(
	const mycms_certificate certificate,
	const int op,
	const unsigned char * const from,
	const size_t from_size,
	unsigned char * const to,
	const size_t to_size,
	const int padding
);

typedef bool (*mycms_certificate_passphrase_callback)(
	const mycms_certificate certificate,
	const char * const what,
	char **p,
	const size_t size
);

mycms_certificate
mycms_certificate_new(
	const mycms_context context
);

bool
mycms_certificate_construct(
	const mycms_certificate certificate
);

bool
mycms_certificate_destruct(
	const mycms_certificate certificate
);

mycms_context
mycms_certificate_get_context(
	const mycms_certificate certificate
);

const void *
mycms_certificate_get_userdata(
	const mycms_certificate certificate
);

bool
mycms_certificate_set_userdata(
	const mycms_certificate certificate,
	const void *userdata
);

const void *
mycms_certificate_get_driverdata(
	const mycms_certificate certificate
);

bool
mycms_certificate_set_driverdata(
	const mycms_certificate certificate,
	const void *userdata
);

bool
mycms_certificate_set_driver_load(
	const mycms_certificate certificate,
	const mycms_certificate_driver_load driver_load
);

bool
mycms_certificate_set_driver_free(
	const mycms_certificate certificate,
	const mycms_certificate_driver_free driver_free
);

bool
mycms_certificate_set_driver_rsa_private_op(
	const mycms_certificate certificate,
	const mycms_certificate_driver_rsa_private_op driver_rsa_private_op
);

bool
mycms_certificate_set_passphrase_callback(
	const mycms_certificate certificate,
	const mycms_certificate_passphrase_callback passphrase_callback
);

bool
mycms_certificate_apply_certificate(
	const mycms_certificate certificate,
	const mycms_blob *blob
);

bool
mycms_certificate_load(
	const mycms_certificate certificate,
	const mycms_dict parameters
);

bool
mycms_certificate_acquire_passphrase(
	const mycms_certificate certificate,
	const char * const what,
	char **p,
	const size_t size
);

#endif
