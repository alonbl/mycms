#ifndef __MYCMS_H
#define __MYCMS_H

#include <stdlib.h>

#include "mycms-certificate.h"
#include "mycms-io.h"
#include "mycms-dict.h"
#include "mycms-list-str.h"
#include "mycms-context.h"

struct mycms_signer_s {
	mycms_blob cert;
	mycms_blob keyid;
	char *digest;
};

MYCMS_LIST_DECLARE(signer, struct mycms_signer_s, signer)

struct __mycms_s;
typedef struct __mycms_s *mycms;

mycms
mycms_new(
	const mycms_context context
);

bool
mycms_construct(
	const mycms mycms
);

bool
mycms_destruct(
	const mycms mycms
);

mycms_context
mycms_get_context(
	const mycms mycms
);

mycms_system
mycms_get_system(
	const mycms mycms
);

mycms_error
mycms_get_error(
	const mycms mycms
);

bool
mycms_sign(
	const mycms mycms __attribute__((unused)),
	const mycms_certificate certificate,
	const mycms_list_str digests,
	const mycms_list_str keyopts,
	const mycms_io cms_in,
	const mycms_io cms_out,
	const mycms_io data_in
);

bool
mycms_verify_list_free(
	const mycms mycms,
	const mycms_list_signer l
);

bool
mycms_verify_list(
	const mycms mycms,
	const mycms_io cms_in,
	mycms_list_signer * const signers
);

bool
mycms_verify(
	const mycms mycms,
	const mycms_io cms_in,
	const mycms_io data_in,
	const mycms_list_signer signers,
	bool * const verified
);

bool
mycms_encrypt(
	const mycms mycms,
	const char * const cipher_name,
	const mycms_list_blob to,
	const mycms_list_str keyopts,
	const mycms_io cms_out,
	const mycms_io data_pt,
	const mycms_io data_ct
);

bool
mycms_encrypt_add(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_list_blob to,
	const mycms_list_str keyopts,
	const mycms_io cms_in,
	const mycms_io cms_out
);

bool
mycms_encrypt_reset(
	const mycms mycms,
	const mycms_list_blob to,
	const mycms_io cms_in,
	const mycms_io cms_out
);

bool
mycms_decrypt(
	const mycms mycms,
	const mycms_certificate certificate,
	const mycms_io cms_in,
	const mycms_io data_pt,
	const mycms_io data_ct
);

#endif
