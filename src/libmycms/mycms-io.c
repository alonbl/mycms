#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "mycms-error-internal.h"
#include "mycms-io-private.h"
#include "mycms-openssl.h"

struct mycms_io_s {
	mycms_context context;
	BIO *bio;
};

mycms_io
mycms_io_new(
	const mycms_context context
) {
	mycms_system system = NULL;
	mycms_io io = NULL;

	if (context == NULL) {
		return NULL;
	}

	if ((system = mycms_context_get_system(context)) == NULL) {
		goto cleanup;
	}

	if ((io = mycms_system_zalloc(system, "io", sizeof(*io))) == NULL) {
		goto cleanup;
	}

	io->context = context;

cleanup:

	return io;
}

bool
mycms_io_construct(
	const mycms_io io
) {
	if (io == NULL) {
		return false;
	}

	return true;
}

bool
mycms_io_destruct(
	const mycms_io io
) {
	bool ret = true;

	if (io != NULL) {
		mycms_system system = mycms_context_get_system(io->context);

		BIO_free(io->bio);
		io->bio = NULL;

		ret = mycms_system_free(system, "io", io) && ret;
	}

	return ret;
}

mycms_context
mycms_io_get_context(
	const mycms_io io
) {
	if (io == NULL) {
		return false;
	}

	return io->context;
}

bool
mycms_io_open_file(
	const mycms_io io,
	const char * const file,
	const char * const mode
) {
	bool ret = false;

	if (io == NULL) {
		return false;
	}

	BIO_free(io->bio);
	io->bio = NULL;

#ifdef ENABLE_IO_DRIVER_FILE
	if ((io->bio = BIO_new_file(file, mode)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(io->context)),
			"io.open",
			MYCMS_ERROR_CODE_IO,
			true,
			"Cannot open '%s' at mode '%s'",
			file,
			mode
		)));
		goto cleanup;
	}
#else
	(void)file;
	(void)mode;
	goto cleanup;
#endif

	ret = true;

cleanup:

	return ret;
}

bool
mycms_io_map_mem(
	const mycms_io io,
	const void *p,
	const size_t s
) {
	bool ret = false;

	if (io == NULL) {
		return false;
	}

	BIO_free(io->bio);
	io->bio = NULL;

	if ((io->bio = BIO_new_mem_buf(p, s)) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(io->context)),
			"io.map",
			MYCMS_ERROR_CODE_MEMORY,
			true,
			"Cannot allocate buffer"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
mycms_io_open_mem(
	const mycms_io io
) {
	bool ret = false;

	if (io == NULL) {
		return false;
	}

	BIO_free(io->bio);
	io->bio = NULL;

	if ((io->bio = BIO_new(BIO_s_mem())) == NULL) {
		_mycms_error_entry_dispatch(_error_entry_openssl_status(_mycms_error_entry_base(
			_mycms_error_capture(mycms_context_get_error(io->context)),
			"io.mem",
			MYCMS_ERROR_CODE_MEMORY,
			true,
			"Cannot allocate buffer"
		)));
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

ssize_t
mycms_io_get_mem_ptr(
	const mycms_io io,
	char **p
) {
	if (io == NULL) {
		return -1;
	}

	return BIO_get_mem_data(io->bio, &p);
}

BIO *
_mycms_io_get_BIO(
	const mycms_io io
) {
	if (io == NULL) {
		return NULL;
	}

	return io->bio;
}
