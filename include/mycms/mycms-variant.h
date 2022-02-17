#ifndef __MYCMS_VARIANT_H
#define __MYCMS_VARIANT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum mycms_variant_type_e {
	mycms_variant_type_none,
	mycms_variant_type_u32,
	mycms_variant_type_u64,
	mycms_variant_type_str,
	mycms_variant_type_blob,
	__mycms_variant_type_end
} mycms_variant_type;

typedef struct mycms_variant_s {
	mycms_variant_type t;
	union {
		uint32_t u32;
		uint64_t u64;
		char str[1024];
		struct {
			unsigned char *d[1024 - sizeof(size_t)];
			size_t s;
		} blob[1];
	} d[1];
} mycms_variant;

#ifdef __cplusplus
}
#endif

#endif
