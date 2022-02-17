#ifndef __MYCMS_INTERNAL_H
#define __MYCMS_INTERNAL_H

#include <mycms/mycms.h>

#include "mycms-crypto.h"

struct _mycms_internal_s {
	char *base_ct;
	char *base_pt;
	char *md_suffix;
	_mycms_crypto crypto;
	mycms_bio bio_random;
	mycms_key_callback key_callback;
	char *encryption_key_id;
};
typedef struct _mycms_internal_s *mycms_internal;

mycms_internal
_mycms_get_internal(
	const mycms mycms
);

#endif
