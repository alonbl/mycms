#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <unistd.h>
#endif

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <mycms/mycms-system-driver-core.h>

#include "mycms-error-internal.h"
#include "mycms-util.h"

struct mycms_system_s {
	const void *userdata;
	struct mycms_system_driver_entry_s driver_entries[256];
	mycms_error error;
};

#if 0
static
mycms_error_entry
__error_entry_errno(
	const mycms_error_entry entry
) {
	char msg[1024];
	int old_errno;

	_mycms_error_entry_prm_add_u32(entry, MYCMS_ERROR_KEY_ERRNO, errno);

	old_errno = errno;
	errno = 0;
	msg[0] = '\0';
	strerror_r(old_errno, msg, sizeof(msg));
	if (errno == 0) {
		_mycms_error_entry_prm_add_str(entry, MYCMS_ERROR_KEY_ERRNO_STR, msg);
	}
	errno = old_errno;

	return entry;
}
#endif

#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT

static
void
__driver_default_explicit_bzero(
	const mycms_system system __attribute__((unused)),
	void * const p,
	const size_t size
) {
#if defined(HAVE_EXPLICIT_BZERO)
	explicit_bzero(p, size);
#elif defined(HAVE_SECUREZEROMEMORY)
	SecureZeroMemory(p, size);
#else
	memset(p, 0, size);
#endif
}

static
void *
__driver_default_realloc(
	const mycms_system system,
	const char * const hint,
	void * const p,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		return NULL;
	}

	if ((ret = realloc(p, size)) == NULL  && size != 0) {
		_mycms_error_entry_dispatch(
			_mycms_error_entry_prm_add_u64(
				_mycms_error_entry_base(
					_mycms_error_capture(system->error),
					hint,
					MYCMS_ERROR_CODE_MEMORY,
					true,
					"Memory allocation failed"
				),
				MYCMS_ERROR_KEY_RESOURCE_SIZE,
				size
			)
		);
	}

	return ret;
}

static
bool
__driver_default_free(
	const mycms_system system __attribute__((unused)),
	const char * const hint __attribute__((unused)),
	void * const p
) {
	free(p);
	return true;
}

static
void *
__driver_default_dlopen(
	const mycms_system system __attribute__((unused)),
	const char *filename,
	const int flags
) {
#ifdef _WIN32
	(void)flags;
	return (void *)LoadLibraryA(filename);
#else
	return dlopen(filename, flags);
#endif
}

static
bool
__driver_default_dlclose(
	const mycms_system system __attribute__((unused)),
	void *handle
) {
#ifdef _WIN32
	return FreeLibrary((HMODULE)handle);
#else
	return dlclose(handle) == 0;
#endif
}

static
void *
__driver_default_dlsym(
	const mycms_system system __attribute__((unused)),
	void *handle,
	const char *symbol
) {
#ifdef _WIN32
	FARPROC r;
	void *p;
	r = GetProcAddress((HMODULE)handle, symbol);
	memcpy(&p, &r, sizeof(p));
	return p;
#else
	return dlsym(handle, symbol);
#endif
}

#pragma GCC diagnostic ignored "-Wcast-function-type"
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ MYCMS_SYSTEM_DRIVER_ID_core_explicit_bzero, (void (*)()) __driver_default_explicit_bzero},
	{ MYCMS_SYSTEM_DRIVER_ID_core_free, (void (*)()) __driver_default_free},
	{ MYCMS_SYSTEM_DRIVER_ID_core_realloc, (void (*)()) __driver_default_realloc},
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlopen, (void (*)()) __driver_default_dlopen},
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlclose, (void (*)()) __driver_default_dlclose},
	{ MYCMS_SYSTEM_DRIVER_ID_core_dlsym, (void (*)()) __driver_default_dlsym},
	{ 0, NULL}
};
#pragma GCC diagnostic pop
#else
static const struct mycms_system_driver_entry_s __DRIVER_ENTRIES[] = {
	{ 0, NULL}
};
#endif

size_t
mycms_system_get_context_size(void) {
	return sizeof(*(mycms_system)NULL);
}

mycms_system
mycms_system_new() {
#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT
	mycms_system system = NULL;
	mycms_system ret = NULL;

	if ((system = realloc(NULL, sizeof(*system))) == NULL) {
		goto cleanup;
	}

	memset(system, 0, sizeof(*system));

	if (!mycms_system_init(system, sizeof(*system))) {
		goto cleanup;
	}

	ret = system;
	system = NULL;

cleanup:

	free(system);

	return ret;
#else
	return NULL;
#endif
}

bool
mycms_system_init(
	const mycms_system system,
	const size_t size
) {
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	if (MYCMS_SYSTEM_CONTEXT_SIZE < mycms_system_get_context_size()) {
		goto cleanup;
	}

	if (size < mycms_system_get_context_size()) {
		goto cleanup;
	}

	mycms_system_clean(system, size);

	mycms_system_driver_register(system, __DRIVER_ENTRIES);

	ret = true;

cleanup:

	return ret;
}

bool
mycms_system_construct(
	const mycms_system system
) {
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	if ((system->error = _mycms_error_new(system)) == NULL) {
		goto cleanup;
	}

	if (!_mycms_error_construct(system->error)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_system_destruct(
	const mycms_system system __attribute__((unused))
) {
	bool ret = true;
#ifdef ENABLE_SYSTEM_DRIVER_DEFAULT
	ret = mycms_system_clean(system, sizeof(*system));
	free(system);
#endif
	return ret;
}

bool
mycms_system_clean(
	const mycms_system system,
	const size_t size
) {
	bool ret = false;

	if (size < mycms_system_get_context_size()) {
		goto cleanup;
	}

	if (system != NULL) {
		mycms_error error = system->error;
		system->error = NULL;
		_mycms_error_destruct(error);
		memset(system, 0, sizeof(*system));
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_system_driver_register(
	const mycms_system system,
	const struct mycms_system_driver_entry_s * const entries
) {
	struct mycms_system_driver_entry_s *t;
	const struct mycms_system_driver_entry_s *s;
	bool ret = false;

	if (system == NULL) {
		return false;
	}

	for (t = system->driver_entries; t->id != 0; t++);
	for (s = entries; s->id != 0; s++);
	s++;

	if (s - entries >= system->driver_entries + sizeof(system->driver_entries) / sizeof(*system->driver_entries) - t) {
		goto cleanup;
	}

	memcpy(t, entries, sizeof(*entries) * (s - entries));

	ret = true;

cleanup:

	return ret;
}

void (*mycms_system_driver_find(
	const mycms_system system,
	const unsigned id
))() {
	struct mycms_system_driver_entry_s *x;
	void (*ret)() = NULL;

	if (system == NULL) {
		return NULL;
	}

	/* TODO: optimize */
	for (x = system->driver_entries; x->id != 0; x++) {
		if (x->id == id) {
			ret = x->f;
		}
	}

	return ret;
}

const void *
mycms_system_get_userdata(
	const mycms_system system
) {
	if (system == NULL) {
		return NULL;
	}

	return system->userdata;
}

bool
mycms_system_set_userdata(
	const mycms_system system,
	const void *userdata
) {
	if (system == NULL) {
		return false;
	}

	system->userdata = userdata;
	return true;
}

mycms_error
mycms_system_get_error(
	const mycms_system system
) {
	if (system == NULL) {
		return NULL;
	}

	return system->error;
}

void
mycms_system_explicit_bzero(
	const mycms_system system,
	void * const p,
	const size_t size
) {
	mycms_system_driver_core_explicit_bzero(system)(system, p, size);
}

void *
mycms_system_realloc(
	const mycms_system system,
	const char * const hint,
	void * const p,
	const size_t size
) {
	return mycms_system_driver_core_realloc(system)(system, hint, p, size);
}

bool
mycms_system_free(
	const mycms_system system,
	const char * const hint,
	void * const p
) {
	mycms_system_driver_core_free(system)(system, hint, p);
	return true;
}

void *
mycms_system_zalloc(
	const mycms_system system,
	const char * const hint,
	const size_t size
) {
	void *ret = NULL;

	if (system == NULL) {
		return NULL;
	}

	if ((ret = mycms_system_realloc(system, hint, NULL, size)) == NULL) {
		goto cleanup;
	}

	mycms_system_explicit_bzero(system, ret, size);

cleanup:

	return ret;
}

char *
mycms_system_strdup(
	const mycms_system system,
	const char * const hint,
	const char * const s
) {
	char *ret = NULL;
	size_t size;

	if (system == NULL) {
		return NULL;
	}

	if (s == NULL) {
		goto cleanup;
	}

	size = strlen(s) + 1;

	if ((ret = mycms_system_realloc(system, hint, NULL, size)) == NULL) {
		goto cleanup;
	}

	memcpy(ret, s, size);

cleanup:

	return ret;
}
