#ifndef __MYCMS_SYSTEM_H
#define __MYCMS_SYSTEM_H

#include <stdbool.h>
#include <stdlib.h>

#include "mycms-error.h"

#ifdef __cplusplus
extern "C" {
#endif

#define __MYCMS_SYSTEM_DRIVER_FUNC_COMMON(group, name) \
	static inline mycms_system_driver_p_##group##_##name mycms_system_driver_##group##_##name (const mycms_system system) { \
		return (mycms_system_driver_p_##group##_##name)mycms_system_driver_find(system, MYCMS_SYSTEM_DRIVER_ID_##group##_##name); \
	}
#if defined(HAVE_C99_VARARGS_MACROS)
#define MYCMS_SYSTEM_DRIVER_FUNC(group, ret, name, ...) \
	typedef ret (*mycms_system_driver_p_##group##_##name)(const mycms_system system __VA_OPT__(,) __VA_ARGS__); \
	__MYCMS_SYSTEM_DRIVER_FUNC_COMMON(group, name)
#elif defined(HAVE_GCC_VARARGS_MACROS)
#define MYCMS_SYSTEM_DRIVER_FUNC(group, ret, name, ...) \
	typedef ret (*mycms_system_driver_p_##group##_##name)(const mycms_system system, ##__VA_ARGS__); \
	__MYCMS_SYSTEM_DRIVER_FUNC_COMMON(group, name)
#else
#error no available varargs macros method
#endif

#define MYCMS_SYSTEM_CONTEXT_SIZE 4096 * 10

struct mycms_system_s;
typedef struct mycms_system_s *mycms_system;

struct mycms_system_driver_entry_s {
	unsigned id;
	void (*f)();
};

size_t
mycms_system_get_context_size(void);

mycms_system
mycms_system_new();

bool
mycms_system_init(
	const mycms_system system,
	const size_t size
);

bool
mycms_system_construct(
	const mycms_system system
);

bool
mycms_system_destruct(
	const mycms_system system
);

bool
mycms_system_clean(
	const mycms_system system,
	const size_t size
);

bool
mycms_system_driver_register(
	const mycms_system system,
	const struct mycms_system_driver_entry_s * const entries
);

void (*mycms_system_driver_find(
	const mycms_system system,
	const unsigned id
))();

const void *
mycms_system_get_userdata(
	const mycms_system system
);

bool
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
);

mycms_error
mycms_system_get_error(
	const mycms_system system
);

void
mycms_system_explicit_bzero(
	const mycms_system system,
	void * const p,
	const size_t size
);

void *
mycms_system_realloc(
	const mycms_system system,
	const char * const hint,
	void * const p,
	const size_t size
);

bool
mycms_system_free(
	const mycms_system system,
	const char * const hint,
	void * const p
);

void *
mycms_system_zalloc(
	const mycms_system system,
	const char * const hint,
	const size_t size
);

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const hint,
	const char * const s
);

#ifdef __cplusplus
}
#endif

#endif
