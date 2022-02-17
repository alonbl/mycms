#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef BUILD_WINDOWS
#include <windows.h>
#else
#include <poll.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif

#endif

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mycms-util-pinentry.h"

struct _mycms_util_pinentry_s {
	mycms_context context;
#ifdef BUILD_WINDOWS
	HANDLE channel;
	HANDLE process;
#else
	int channel;
	pid_t process;
#endif
	int dummy;
};

static const struct _mycms_util_pinentry_s __MYCMS_ENTRY_INIT = {
	NULL,
#ifdef BUILD_WINDOWS
	INVALID_HANDLE_VALUE,
	INVALID_HANDLE_VALUE,
#else
	-1,
	-1,
#endif
	0
};

#ifndef BUILD_WINDOWS
extern char **environ;

static
inline
int
pidfd_open(
        pid_t pid,
        unsigned int flags
) {
        return syscall(__NR_pidfd_open, pid, flags);
}
#endif

#ifdef BUILD_WINDOWS

static
bool
__pinentry_native_exec(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	mycms_system system = NULL;
	STARTUPINFOA startinfo;
	PROCESS_INFORMATION procinfo;
	OVERLAPPED overlapped;
	HANDLE h = INVALID_HANDLE_VALUE;
	char name_unique[1024];
	bool ret = false;

	if ((system = mycms_context_get_system(pinentry->context)) == NULL) {
		goto cleanup;
	}

	mycms_system_explicit_bzero(system, &startinfo, sizeof(startinfo));
	startinfo.hStdInput = startinfo.hStdOutput = startinfo.hStdError = INVALID_HANDLE_VALUE;
	mycms_system_explicit_bzero(system, &procinfo, sizeof(procinfo));
	procinfo.hProcess = INVALID_HANDLE_VALUE;
	mycms_system_explicit_bzero(system, &overlapped, sizeof(overlapped));
	overlapped.hEvent = CreateEventA(NULL, TRUE, FALSE, NULL);

	snprintf(
		name_unique,
		sizeof(name_unique),
		"\\\\.\\pipe\\mycms-%08lx-%08lx",
		GetCurrentProcessId(),
		GetCurrentThreadId()
	);

	if ((pinentry->channel = CreateNamedPipeA(
		name_unique,
		PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE,
		PIPE_UNLIMITED_INSTANCES,
		0,
		0,
		INFINITE,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		goto cleanup;
	}

	if (!ConnectNamedPipe(pinentry->channel, &overlapped)) {
		if (GetLastError() != ERROR_IO_PENDING) {
			goto cleanup;
		}
	}

	if ((h = CreateFileA(
		name_unique,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) == INVALID_HANDLE_VALUE) {
		goto cleanup;
	}


	{
		DWORD dw;
		if (!GetOverlappedResult(
			pinentry->channel,
			&overlapped,
			&dw,
		TRUE)) {
			goto cleanup;
		}
	}

	startinfo.cb = sizeof(startinfo);
	startinfo.dwFlags = STARTF_USESTDHANDLES;
	if (!DuplicateHandle(
		GetCurrentProcess(),
		h,
		GetCurrentProcess(),
		&startinfo.hStdInput,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}
	if (!DuplicateHandle(
		GetCurrentProcess(),
		h,
		GetCurrentProcess(),
		&startinfo.hStdOutput,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}
	if (!DuplicateHandle(
		GetCurrentProcess(),
		GetStdHandle(STD_ERROR_HANDLE),
		GetCurrentProcess(),
		&startinfo.hStdError,
		0,
		TRUE,
		DUPLICATE_SAME_ACCESS
	)) {
		goto cleanup;
	}

	if (!CreateProcessA(
		prog,
		NULL,
		NULL,
		NULL,
		TRUE,
		0,
		NULL,
		NULL,
		&startinfo,
		&procinfo
	)) {
		goto cleanup;
	}

	pinentry->process = procinfo.hProcess;
	procinfo.hProcess = INVALID_HANDLE_VALUE;

	ret = true;

cleanup:

	if (h != INVALID_HANDLE_VALUE) {
		CloseHandle(h);
		h = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdInput != INVALID_HANDLE_VALUE) {
		CloseHandle(startinfo.hStdInput);
		startinfo.hStdInput = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdOutput != INVALID_HANDLE_VALUE) {
		CloseHandle(startinfo.hStdOutput);
		startinfo.hStdOutput = INVALID_HANDLE_VALUE;
	}

	if (startinfo.hStdError != INVALID_HANDLE_VALUE) {
		CloseHandle(startinfo.hStdError);
		startinfo.hStdError = INVALID_HANDLE_VALUE;
	}

	return ret;
}

static
bool
__pinentry_native_close(
	const _mycms_pinentry pinentry
) {
	mycms_system system = NULL;
	bool ret = false;

	if ((system = mycms_context_get_system(pinentry->context)) == NULL) {
		goto cleanup;
	}

	if (pinentry->channel != INVALID_HANDLE_VALUE) {
		CloseHandle(pinentry->channel);
		pinentry->channel = INVALID_HANDLE_VALUE;
	}

	if (pinentry->process != INVALID_HANDLE_VALUE) {

		if (WaitForSingleObject(pinentry->process, 5000) == WAIT_OBJECT_0) {
			TerminateProcess(pinentry->process, 1);
		}

		CloseHandle(pinentry->process);
		pinentry->process = INVALID_HANDLE_VALUE;
	}

	ret = true;

cleanup:

	return ret;
}

static
ssize_t
__pinentry_native_read(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	DWORD r;

	if ((system = mycms_context_get_system(pinentry->context)) == NULL) {
		return -1;
	}

	if (ReadFile(pinentry->channel, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

static
ssize_t
__pinentry_native_write(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	mycms_system system = NULL;
	DWORD r;

	if ((system = mycms_context_get_system(pinentry->context)) == NULL) {
		return -1;
	}

	if (WriteFile(pinentry->channel, p, s, &r, NULL)) {
		return r;
	}
	return -1;
}

#else

#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>

static
bool
__pinentry_native_exec(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	char tty[1024];
	const char * const args[] = {
		prog,
		"--ttyname",
		tty,
		NULL
	};
	int sockets[2] = {-1, -1};
	bool ret = false;
	pid_t child;

	if (ttyname_r(0, tty, sizeof(tty)) != 0) {
		tty[0] = '\0';
	}

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) < 0) {
		goto cleanup;
	}

	if ((child = fork()) == -1) {
		goto cleanup;
	}

	if (child == 0) {
		struct rlimit r;
		unsigned long i;

		close(sockets[0]);

		if (dup2(sockets[1], 0) == -1) {
			goto child_cleanup;
		}
		if (dup2(sockets[1], 1) == -1) {
			goto child_cleanup;
		}

		if (getrlimit(RLIMIT_NOFILE, &r) == -1) {
			goto child_cleanup;
		}
		for (i = 4;i < r.rlim_cur;i++) {
			close(i);
		}

		if (execve(
			prog,
			(char **)args,
			environ
		) == -1) {
			goto child_cleanup;
		}

	child_cleanup:

		_exit(1);
	}

	pinentry->channel = sockets[0];
	sockets[0] = -1;
	pinentry->process = child;

	ret = true;

cleanup:

	if (sockets[0] != -1) {
		close(sockets[0]);
		sockets[0] = -1;
	}

	if (sockets[1] != -1) {
		close(sockets[1]);
		sockets[1] = -1;
	}

	return ret;
}

static
bool
__pinentry_native_close(
	const _mycms_pinentry pinentry
) {
	if (pinentry->channel != -1) {
		close(pinentry->channel);
		pinentry->channel = -1;
	}

	if (pinentry->process != -1) {
		int fd;
		if ((fd = pidfd_open(pinentry->process, 0)) == -1) {
			if (errno == ENOSYS) {
				kill(pinentry->process, SIGKILL);
				waitpid(pinentry->process, NULL, 0);
			}
		} else {
			struct pollfd pfd = {fd, POLLIN, 0};
			int r;
			while (
				(r = poll(&pfd, 1, 5000)) == -1 &&
				errno == EINTR
			);
			if (r == 0) {
				kill(pinentry->process, SIGKILL);
			}
			waitpid(pinentry->process, NULL, 0);
			close(fd);
		}

		pinentry->process = -1;
	}

	return true;
}

static
ssize_t
__pinentry_native_read(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	ssize_t r = -1;

	while (1) {
		if ((r = read(pinentry->channel, p, s)) < 0) {
			int e = errno;
			if (e != EAGAIN && e != EINTR) {
				break;
			}
		} else {
			break;
		}
	}

	return r;
}

static
ssize_t
__pinentry_native_write(
	const _mycms_pinentry pinentry,
	void * const p,
	size_t s
) {
	ssize_t r = -1;

	while (1) {
		if ((r = write(pinentry->channel, p, s)) < 0) {
			int e = errno;
			if (e != EAGAIN && e != EINTR) {
				break;
			}
		} else {
			break;
		}
	}

	return r;
}

#endif

static
bool
__pinentry_readline(
	const _mycms_pinentry pinentry,
	char * const line,
	const size_t size
) {
	char *p = line;
	size_t s = size;
	ssize_t r;
	bool ret = false;

	while (s > 0) {
		if ((r = __pinentry_native_read(pinentry, p, sizeof(*p))) < 0) {
			goto cleanup;
		} else if (r == 0) {
			goto cleanup;
		}

		s--;
		if (*p == '\n') {
			*p = '\0';
			break;
		}
		p++;
	}

	if (s == 0) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

static
bool
__pinentry_read_ok(
	const _mycms_pinentry pinentry
) {
	char buffer[1024];
	bool ret = false;

	if (!__pinentry_readline(pinentry, buffer, sizeof(buffer))) {
		goto cleanup;
	}

	if (strncmp(buffer, "OK", 2)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

static
bool
__pinentry_read_data(
	const _mycms_pinentry pinentry,
	char * const buffer,
	const size_t size
) {
	char b[1024];
	bool ret = false;

	if (!__pinentry_readline(pinentry, b, sizeof(b))) {
		goto cleanup;
	}

	if (strncmp(b, "D ", 2)) {
		goto cleanup;
	}

	if (strlen(b) - 2 >= size) {
		goto cleanup;
	}

	strcpy(buffer, b+2);

	ret = true;

cleanup:

	return ret;
}

static
bool
__pinentry_printf(
	const _mycms_pinentry pinentry,
	const char *format,
	...
) __attribute__ ((format (printf, 2, 3)));

static
bool
__pinentry_printf(
	const _mycms_pinentry pinentry,
	const char *format,
	...
) {
	va_list args;
	char buffer[1024];
	char *p;
	size_t s;
	ssize_t r;
	bool ret = false;

	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	p = buffer;
	s = strlen(buffer);
	while (s > 0) {
		if ((r = __pinentry_native_write(pinentry, p, s)) < 0) {
			goto cleanup;
		} else if (r == 0) {
			goto cleanup;
		}
		p += r;
		s -= r;
	}

	ret = true;

cleanup:

	return ret;
}

_mycms_pinentry
_mycms_util_pinentry_new(
	const mycms_context context
) {
	mycms_system system = NULL;
	_mycms_pinentry pinentry = NULL;

	if (context == NULL) {
		goto cleanup;
	}

	if ((system = mycms_context_get_system(context)) == NULL) {
		goto cleanup;
	}

	if ((pinentry = mycms_system_zalloc(system, "pinentry", sizeof(*pinentry))) == NULL) {
		goto cleanup;
	}

	memcpy(pinentry, &__MYCMS_ENTRY_INIT, sizeof(*pinentry));

	pinentry->context = context;

cleanup:

	return pinentry;
}

bool
_mycms_util_pinentry_construct(
	const _mycms_pinentry pinentry,
	const char * const prog
) {
	bool ret = false;

	if (pinentry == NULL) {
		goto cleanup;
	}

	if (!__pinentry_native_exec(pinentry, prog)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

bool
_mycms_util_pinentry_destruct(
	const _mycms_pinentry pinentry
) {
	mycms_system system = NULL;
	bool ret = false;

	if (pinentry == NULL) {
		ret = true;
		goto cleanup;
	}

	if ((system = mycms_context_get_system(pinentry->context)) == NULL) {
		goto cleanup;
	}

	__pinentry_printf(pinentry, "BYE\n");

	if (!__pinentry_native_close(pinentry)) {
		goto cleanup;
	}

	if (!mycms_system_free(system, "pinentry", pinentry)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}

mycms_context
_mycms_util_pinentry_get_context(
	const _mycms_pinentry pinentry
) {
	if (pinentry == NULL) {
		return NULL;
	}

	return pinentry->context;
}

bool
_mycms_util_pinentry_exec(
	const _mycms_pinentry pinentry,
	const char * const title,
	const char * const prompt,
	char * const pin,
	const size_t pin_size
) {
	bool ret = false;

	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "SETTITLE %s\n", title)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "SETPROMPT %s\n", prompt)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}
	if (!__pinentry_printf(pinentry, "GETPIN\n")) {
		goto cleanup;
	}
	if (!__pinentry_read_data(pinentry, pin, pin_size)) {
		goto cleanup;
	}
	if (!__pinentry_read_ok(pinentry)) {
		goto cleanup;
	}

	ret = true;

cleanup:

	return ret;
}
