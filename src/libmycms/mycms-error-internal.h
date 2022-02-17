#ifndef __MYCMS_ERROR_INTERNAL_H
#define __MYCMS_ERROR_INTERNAL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>

#include <mycms/mycms-error.h>
#include <mycms/mycms-system.h>

void
_mycms_error_register_key_desc(
	struct mycms_error_desc_s * const _desc,
	const size_t n
);

mycms_error
_mycms_error_new(
	const mycms_system system
);

bool
_mycms_error_construct(
	const mycms_error error
);

bool
_mycms_error_destruct(
	const mycms_error error
);

mycms_error_entry
_mycms_error_entry_new(
	const mycms_error error
);

void
_mycms_error_entry_dispatch(
	const mycms_error_entry entry
);

mycms_variant *
_mycms_error_entry_prm_new_variant(
	const mycms_error_entry entry,
	const int k
);

mycms_error_entry
_mycms_error_entry_prm_add_u32(
	const mycms_error_entry entry,
	const int k,
	const uint32_t u32
);

mycms_error_entry
_mycms_error_entry_prm_add_u64(
	const mycms_error_entry entry,
	const int k,
	const uint32_t u64
);

mycms_error_entry
_mycms_error_entry_prm_add_str(
	const mycms_error_entry entry,
	const int k,
	const char * const str
);

mycms_error_entry
_mycms_error_entry_prm_add_blob(
	const mycms_error_entry entry,
	const int k,
	const unsigned char * const d,
	const size_t s
);

mycms_error_entry
_mycms_error_entry_vsprintf(
	const mycms_error_entry entry,
	const int k,
	const char * const format,
	va_list ap
);

mycms_error_entry
_mycms_error_entry_sprintf(
	const mycms_error_entry entry,
	const int k,
	const char * const format,
	...
) __attribute__((format(printf, 3, 4)));

mycms_error_entry
_mycms_error_capture_indirect(
	const mycms_error error,
	const char * const file,
	const int line,
	const char * const func
);
#define _mycms_error_capture(error) \
	_mycms_error_capture_indirect((error), __FILE__, __LINE__, __func__)

mycms_error_entry
_mycms_error_entry_base(
	const mycms_error_entry entry,
	const char * const hint,
	const uint32_t code,
	const bool authoritative,
	const char * const format,
	...
) __attribute__((format(printf, 5, 6)));

#endif
