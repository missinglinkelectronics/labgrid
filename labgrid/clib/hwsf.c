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


#define LIBNAME "libhwsf"

#if !defined(RTLD_NEXT)
#define LIBCPATH "libc.so.6"
#endif

/* uncomment and adjust this line to define the application that this library is
targeted at. Keep in mind that the library will not work with any other program
if this is specified!*/
//#define DEF_ENV_PRG_NAME "hw_server"

#define ENV_DBG "HWSF_DBG"
#define ENV_DEV "HWSF_DEV"
#define ENV_PRG_NAME "HWSF_PRG_NAME"

//TODO: how long can a USB serial be?
#define DEV_SERIAL_PATH_LEN 255 + 1
#define DEV_ROOT_PATH "/sys/bus/usb/devices/"

enum {
	LOG_TYPE_DBG,
	LOG_TYPE_WARN,
	LOG_TYPE_ERR,
};

struct hwsf_data {
	pid_t pid;
	pid_t ppid;
	int debug;

	unsigned int en_dev_serial;
	char dev_serial[DEV_SERIAL_PATH_LEN];

	unsigned int en_dev_path;
	char dev_path[DEV_SERIAL_PATH_LEN];

	unsigned int en_dev_num;
	char dev_num[3 + 1];

	int desc_fd;
};

struct usb_devdesc {
	uint8_t bLength;
	uint8_t bDescriptorType;
	uint16_t bcdUSB;
	uint8_t bDeviceClass;
	uint8_t bDeviceSubClass;
	uint8_t bDeviceProtocol;
	uint8_t bMaxPacketSize0;
	uint16_t idVendor;
	uint16_t idProduct;
	uint16_t bcdDevice;
	uint8_t iManufacturer;
	uint8_t iProduct;
	uint8_t iSerialNumber;
	uint8_t bNumConfigurations;
};


struct hwsf_data _data;
struct hwsf_data *data;

static int (*libc_open)(const char *, int, ...);
static int (*libc_openat)(int, const char *, int, ...);
static int (*libc_open64)(const char *, int, ...);
static int (*libc_close)(int);
static int (*libc_read)(int, void *, size_t);


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
	all further logging from this library will appear with
	the new logging tag! e.g: if you use the Library with the quartus
	jtagd the logging tag will change from filsel to jtagd*/
	openlog("hwsf", LOG_PID, 0);

	data = &_data;
	memset(data, 0, sizeof(*data));

	data->pid = getpid();
	data->ppid = getppid();
	data->desc_fd = -1;

	*(void **)(&libc_open) = getlibcsym("open");
	*(void **)(&libc_openat) = getlibcsym("openat");
	*(void **)(&libc_open64) = getlibcsym("open64");
	*(void **)(&libc_close) = getlibcsym("close");
	*(void **)(&libc_read) = getlibcsym("read");

	e = getenv(ENV_DBG);
	if (e)
		data->debug = 1;

	e = getenv(ENV_PRG_NAME);
#ifdef DEF_ENV_PRG_NAME
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
		if (strcmp(s, e))
			return;
	}


	e = getenv(ENV_DEV);
	if (!e) {
		log_warn(data, "%s is unset\n", ENV_DEV);
		return;
	}

	if (!strncmp(e, "id:", 3)) {
		e += 3;

		strncpy(data->dev_serial, e, sizeof(data->dev_serial) - 1);
		data->dev_serial[sizeof(data->dev_serial) - 1] = '\0';
		data->en_dev_serial = 1;
		log_dbg(data, "dev_serial: %s\n", data->dev_serial);

	} else if (!strncmp(e, "path:", 5)) {
		e += 5;

		strncpy(data->dev_path, e, sizeof(data->dev_path) - 1);
		data->dev_path[sizeof(data->dev_path) - 1] = '\0';
		data->en_dev_path = 1;
		log_dbg(data, "dev_num: %s\n", data->dev_path);

	} else if (!strncmp(e, "num:", 4)) {
		e += 4;

		strncpy(data->dev_num, e, sizeof(data->dev_num) - 1);
		data->dev_num[sizeof(data->dev_num) - 1] = '\0';
		data->en_dev_num = 1;
		log_dbg(data, "dev_num: %s\n", data->dev_num);
	}
}

/**
 * Read file @sibling in the same directory the file is in @pathname
 * points. @last_slash points to the slash (/) before the final
 * name part of @pathname .
 * The read contents of up to @size bytes is stored in @buf .
 */
static int read_desc_sibling(const char *pathname, char *last_slash,
			     const char *sibling, void *buf, size_t size)
{
	int lsi;
	char sib_path[255];
	int sib_fd;
	int n;

	/* construct dirname(pathname) + "/" + sibling */
	lsi = last_slash - pathname + 1;
	if ((lsi + strlen(sibling)) > (sizeof(sib_path) - 1))
		return -1;

	strncpy(sib_path, pathname, lsi);
	strcpy(sib_path + lsi, sibling);

	/* open sibling attribute */
	sib_fd = open(sib_path, O_RDONLY);
	if (sib_fd == -1) {
		if (errno == ENOENT)
			return -1;

		log_err(data, "failed to open %s for reading: (%d) %s\n",
			sib_path, errno, strerror(errno));
		return -1;
	}

	n = read(sib_fd, buf, size);
	if (n == -1)
		log_err(data, "failed to read from %s: (%d) %s\n",
			sib_path, errno, strerror(errno));

	(void)close(sib_fd);

	return n;
}

/**
 * Determine if @pathname matches "/sys/bus/usb/devices/.../descriptors"
 * and if it is the descriptors attribute of the USB device specified
 * in @data .
 * Returns 0, if @pathname does not match or both conditions evaluate to true,
 * otherwise returns 1.
 */
static int match_desc_except(struct hwsf_data *data, const char *pathname)
{
	int rc;
	int saved_errno;
	char *bn;

	rc = 0;
	saved_errno = errno;

	if (strncmp(pathname, DEV_ROOT_PATH, strlen(DEV_ROOT_PATH)))
		goto out;

	if (strlen(pathname) <= 21)
		goto out;

	bn = strrchr(pathname, '/');
	if (strcmp(bn, "/descriptors"))
		goto out;

	if (data->en_dev_serial) {
		int n;
		char buf[sizeof(data->dev_serial)];

		n = read_desc_sibling(pathname, bn, "serial", buf, sizeof(buf));
		if (n == -1) {
			rc = 1;
			goto out;
		}

		buf[n - 1] = '\0';
		if (!strcmp(buf, data->dev_serial)) {
			log_dbg(data, "dev_serial match %s\n", pathname);
			goto out;
		}

		log_dbg(data, "dev_serial spoof %s\n", pathname);
		rc = 1;
		goto out;

	} else if (data->en_dev_path) {
		char *dn;

		dn = bn - 1;
		while (*dn != '/')
			dn--;
		dn++;

		if (strlen(data->dev_path) == (bn - dn))
			if (!strncmp(dn, data->dev_path, bn - dn)) {
				log_dbg(data, "dev_path match %s\n", pathname);
				goto out;
			}

		log_dbg(data, "dev_path spoof %s\n", pathname);
		rc = 1;
		goto out;

	} else if (data->en_dev_num) {
		int n;
		/* devnum: up to 3 digits + \n */
		char buf[sizeof(data->dev_num)];

		n = read_desc_sibling(pathname, bn, "devnum", buf, sizeof(buf));
		if (n == -1) {
			rc = 1;
			goto out;
		};

		/* replace \n by \0 */
		buf[n - 1] = '\0';

		if (!strcmp(buf, data->dev_num)) {
			log_dbg(data, "dev_num match %s\n", pathname);
			goto out;
		}

		log_dbg(data, "dev_num spoof %s\n", pathname);
		rc = 1;
		goto out;
	}

out:
	errno = saved_errno;
	return rc;
}

int open(const char *pathname, int flags, ...)
{
	mode_t mode;
	int is_desc;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;

		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	/* decide if read()s on to be opened @pathname are to be intercepted --
	 * if @pathname points to a sysfs USB descriptor attribute NOT specified
	 * in @data .
	 */
	is_desc = match_desc_except(data, pathname);

	rc = libc_open(pathname, flags, mode);
	if (rc == -1)
		return -1;

	if (is_desc) {
		if (data->desc_fd != -1)
			log_err(data, "desc_fd already occupied\n");
		data->desc_fd = rc;
	}

	return rc;
}

int openat(int dirfd, const char *pathname, int flags, ...)
{
	mode_t mode;
	int is_desc;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;

		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	/* decide if read()s on to be opened @pathname are to be intercepted --
	 * if @pathname points to a sysfs USB descriptor attribute NOT specified
	 * in @data .
	 */
	is_desc = match_desc_except(data, pathname);

	rc = libc_openat(dirfd, pathname, flags, mode);
	if (rc == -1)
		return -1;

	if (is_desc) {
		if (data->desc_fd != -1)
			log_err(data, "desc_fd already occupied\n");
		data->desc_fd = rc;
	}

	return rc;
}

int open64(const char *pathname, int flags, ...)
{
	mode_t mode;
	int is_desc;
	int rc;

	if (flags & O_CREAT) {
		va_list vl;

		va_start(vl, flags);
		mode = va_arg(vl, mode_t);
		va_end(vl);
	} else {
		mode = 0;
	}

	is_desc = match_desc_except(data, pathname);

	rc = libc_open64(pathname, flags, mode);
	if (rc == -1)
		return -1;

	if (is_desc) {
		if (data->desc_fd != -1)
			log_err(data, "desc_fd already occupied\n");
		data->desc_fd = rc;
	}

	return rc;
}

int close(int fd)
{
	if (data->desc_fd == fd)
		data->desc_fd = -1;

	return libc_close(fd);
}

ssize_t read(int fd, void *buf, size_t count)
{
	int rc;
	struct usb_devdesc *dd;

	/* should we intercept read()s from @fd */
	if ((data->desc_fd == -1) || (data->desc_fd != fd))
		return libc_read(fd, buf, count);

	rc = libc_read(fd, buf, count);
	if (rc == -1)
		return -1;

	/* spoof idVendor and idProduct fields of USB device descriptor */
	if (rc >= sizeof(*dd)) {
		dd = buf;
		dd->idVendor = 0xffff;
		dd->idProduct = 0xffff;
	} else {
		log_err(data, "short read, skip spoofing\n");
	}

	return rc;
}
