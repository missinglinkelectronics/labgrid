/*
 * hwsf.c - LD_PRELOAD library to intercept read access to
 *          /sys/bus/usb/devices/<path>/descriptors and spoof
 *          all idVendor and idProduct fields except for one
 *          single USB device
 *
 * Copyright (C) 2019  Joachim Foerster <JOFT@gmx.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2, only - as published by the Free Software Foundation.
 * The usual option to use any later version is hereby excluded.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* TODO:
 * - make sure various max string lengths are correct
 * - match non-absolute @pathname, considering cwd
 * - be aware of multiple open files to be intercepted
 * - short read()s on descriptors skips spoofing
 */

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <dlfcn.h>


#define LIBNAME "libfilsel"

#if !defined(RTLD_NEXT)
#define LIBCPATH "libc.so.6"
#endif

//#define DEF_ENV_PRG_NAME "hw_server"

#define ENV_DBG "FILSEL_DBG"
#define ENV_ORG_PATH "FILSEL_ORG_PATH"
#define ENV_DEST_PATH "FILSEL_DEST_PATH"

#define ENV_PRG_NAME "FILSEL_PROG_NAME"
 
typedef ssize_t (*real_read_t)(int, void *, size_t);

enum {
	LOG_TYPE_DBG,
	LOG_TYPE_WARN,
	LOG_TYPE_ERR,
};

struct filsel_data {
	pid_t pid;
	pid_t ppid;
	int debug;

	int active;

	char org_path[4096];

	char dest_path[4096];

	unsigned int en_dev_num;
	char dev_num[3 + 1];

	int desc_fd;
};


struct filsel_data _data;
struct filsel_data *data;

static int (*libc_open)(const char *, int, ...);
static int (*libc_openat)(int, const char *, int, ...);
static int (*libc_open64)(const char *, int, ...);


#define _log(data, type, fmt, ...) \
	if ((type != LOG_TYPE_DBG) || (data)->debug) \
		syslog(LOG_USER | LOG_DEBUG, \
			"[" LIBNAME ": %s pid % 5d p % 5d %20s] %s() " fmt, \
			((type == LOG_TYPE_DBG) ? "DBG " : \
			 (type == LOG_TYPE_WARN) ? "WARN" : \
			"ERR "), \
			(data)->pid, (data)->ppid, program_invocation_name, \
			__func__, ##__VA_ARGS__)
#define log_dbg(data, ...) _log(data, LOG_TYPE_DBG, ##__VA_ARGS__)
#define log_warn(data, ...) _log(data, LOG_TYPE_WARN, ##__VA_ARGS__)
#define log_err(data, ...) _log(data, LOG_TYPE_ERR, ##__VA_ARGS__)


static void *getlibcsym(char *sym)
{
	void *handle;
	char *error;
	void *orig_sym;

#if defined(RTLD_NEXT)
	handle = RTLD_NEXT;
#else
	handle = dlopen(LIBCPATH, RTLD_LAZY);
	if (!handle) {
		error = dlerror();
		log_err(data, "%s\n", error);
		exit(EXIT_FAILURE);
	}
#endif

	orig_sym = dlsym(handle, sym);
	error = dlerror();
	if (error) {
		log_err(data, "%s\n", error);
		exit(EXIT_FAILURE);
	}
	return orig_sym;
}

void __attribute ((constructor)) init(void)
{
	char *e;

	/*Attention: if the invoked program opens syslog as well,
	all further logging from this library will appear with the new logging tag!
	e.g: if you use the Library with the quartus jtagd the logging tag will change from filsel to jtagd*/
	openlog("filsel", LOG_PID, 0);

	data = &_data;
	memset(data, 0, sizeof(*data));

	data->pid = getpid();
	data->ppid = getppid();
	data->desc_fd = -1;

	*(void **)(&libc_open) = getlibcsym("open");
	*(void **)(&libc_openat) = getlibcsym("openat");
	*(void **)(&libc_open64) = getlibcsym("open64");

	e = getenv(ENV_DBG);
	if (e)
		data->debug = 1;


	data->active = 1;
	e = getenv(ENV_PRG_NAME);
#ifdef  DEF_ENV_PRG_NAME
	if (!e)
		e = DEF_ENV_PRG_NAME;
#endif
	if (e) {
		char *s;

		s = strrchr(program_invocation_name, '/');
		if (s)
			s++;
		else
			s = program_invocation_name;

		log_dbg(data, "pin: program_invocation_name: %s\n", s);
		if (strcmp(s, e)){
		     data->active = 0;
		     return;
		}
	}


	e = getenv(ENV_ORG_PATH);
	if (!e) {
		log_warn(data, "%s is unset\n", ENV_ORG_PATH);
		data->active = 0;
		return;
	}
	strncpy(data->org_path, e, strlen(e));

	e = getenv(ENV_DEST_PATH);
	if (!e) {
		log_warn(data, "%s is unset\n", ENV_DEST_PATH);
		data->active = 0;
		return;
	}
	strncpy(data->dest_path, e, strlen(e));
}

int open(const char *pathname, int flags, ...)
{
	mode_t mode;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;

		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	if (!data->active)
		return libc_open64(pathname, flags, mode);

	if (strncmp(data->org_path, pathname, strlen(data->org_path)) == 0) {
		log_dbg(data, "Spoofing Path from %s to %s\n",data->org_path,data->dest_path);
		rc = libc_open(data->dest_path, flags, mode);
	}else{
		rc = libc_open(pathname, flags, mode);
	}

	return rc;
}


int openat(int dirfd, const char *pathname, int flags, ...)
{
	mode_t mode;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;

		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	if (!data->active)
		return libc_open64(pathname, flags, mode);

	if (strncmp(data->org_path, pathname, strlen(data->org_path)) == 0) {
		log_dbg(data, "Spoofing Path from %s to %s\n",data->org_path,data->dest_path);
		rc = libc_openat(dirfd, data->dest_path, flags, mode);
	}else{
		rc = libc_openat(dirfd, pathname, flags, mode);
	}

	return rc;
}

int open64(const char *pathname, int flags, ...)
{
	mode_t mode;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;
		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	if (!data->active)
		return libc_open64(pathname, flags, mode);

	if (strncmp(data->org_path, pathname, strlen(data->org_path)) == 0) {
		log_dbg(data, "Spoofing Path from %s to %s\n",data->org_path,data->dest_path);
		rc = libc_open64(data->dest_path, flags, mode);
	}else{
		rc = libc_open64(pathname, flags, mode);
	}

	return rc;
}
