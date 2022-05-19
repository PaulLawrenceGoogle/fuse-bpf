// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright 2021 Google LLC
 */

#include "test_fuse.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/xattr.h>

#include <linux/unistd.h>

#include <uapi/linux/fuse.h>
#include <uapi/linux/bpf.h>

struct _test_options test_options;

struct s s(const char *s1)
{
	struct s s = {0};

	if (!s1)
		return s;

	s.s = malloc(strlen(s1) + 1);
	if (!s.s)
		return s;

	strcpy(s.s, s1);
	return s;
}

struct s sn(const char *s1, const char *s2)
{
	struct s s = {0};

	if (!s1)
		return s;

	s.s = malloc(s2 - s1 + 1);
	if (!s.s)
		return s;

	strncpy(s.s, s1, s2 - s1);
	s.s[s2 - s1] = 0;
	return s;
}

int s_cmp(struct s s1, struct s s2)
{
	int result = -1;

	if (!s1.s || !s2.s)
		goto out;
	result = strcmp(s1.s, s2.s);
out:
	free(s1.s);
	free(s2.s);
	return result;
}

struct s s_cat(struct s s1, struct s s2)
{
	struct s s = {0};

	if (!s1.s || !s2.s)
		goto out;

	s.s = malloc(strlen(s1.s) + strlen(s2.s) + 1);
	if (!s.s)
		goto out;

	strcpy(s.s, s1.s);
	strcat(s.s, s2.s);
out:
	free(s1.s);
	free(s2.s);
	return s;
}

struct s s_splitleft(struct s s1, char c)
{
	struct s s = {0};
	char *split;

	if (!s1.s)
		return s;

	split = strchr(s1.s, c);
	if (split)
		s = sn(s1.s, split);

	free(s1.s);
	return s;
}

struct s s_splitright(struct s s1, char c)
{
	struct s s2 = {0};
	char *split;

	if (!s1.s)
		return s2;

	split = strchr(s1.s, c);
	if (split)
		s2 = s(split + 1);

	free(s1.s);
	return s2;
}

struct s s_word(struct s s1, char c, size_t n)
{
	while (n--)
		s1 = s_splitright(s1, c);
	return s_splitleft(s1, c);
}

struct s s_path(struct s s1, struct s s2)
{
	return s_cat(s_cat(s1, s("/")), s2);
}

struct s s_pathn(size_t n, struct s s1, ...)
{
	va_list argp;

	va_start(argp, s1);
	while (--n)
		s1 = s_path(s1, va_arg(argp, struct s));
	va_end(argp);
	return s1;
}

int s_link(struct s src_pathname, struct s dst_pathname)
{
	int res;

	if (src_pathname.s && dst_pathname.s) {
		res = link(src_pathname.s, dst_pathname.s);
	} else {
		res = -1;
		errno = ENOMEM;
	}

	free(src_pathname.s);
	free(dst_pathname.s);
	return res;
}

int s_symlink(struct s src_pathname, struct s dst_pathname)
{
	int res;

	if (src_pathname.s && dst_pathname.s) {
		res = symlink(src_pathname.s, dst_pathname.s);
	} else {
		res = -1;
		errno = ENOMEM;
	}

	free(src_pathname.s);
	free(dst_pathname.s);
	return res;
}


int s_mkdir(struct s pathname, mode_t mode)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = mkdir(pathname.s, mode);
	free(pathname.s);
	return res;
}

int s_rmdir(struct s pathname)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = rmdir(pathname.s);
	free(pathname.s);
	return res;
}

int s_unlink(struct s pathname)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = unlink(pathname.s);
	free(pathname.s);
	return res;
}

int s_open(struct s pathname, int flags, ...)
{
	va_list ap;
	int res;

	va_start(ap, flags);
	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	if (flags & (O_CREAT | O_TMPFILE))
		res = open(pathname.s, flags, va_arg(ap, mode_t));
	else
		res = open(pathname.s, flags);

	free(pathname.s);
	va_end(ap);
	return res;
}

int s_openat(int dirfd, struct s pathname, int flags, ...)
{
	va_list ap;
	int res;

	va_start(ap, flags);
	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	if (flags & (O_CREAT | O_TMPFILE))
		res = openat(dirfd, pathname.s, flags, va_arg(ap, mode_t));
	else
		res = openat(dirfd, pathname.s, flags);

	free(pathname.s);
	va_end(ap);
	return res;
}

int s_creat(struct s pathname, mode_t mode)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = open(pathname.s, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	free(pathname.s);
	return res;
}

int s_mkfifo(struct s pathname, mode_t mode)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = mknod(pathname.s, S_IFIFO | mode, 0);
	free(pathname.s);
	return res;
}

int s_stat(struct s pathname, struct stat *st)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = stat(pathname.s, st);
	free(pathname.s);
	return res;
}

int s_statfs(struct s pathname, struct statfs *st)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = statfs(pathname.s, st);
	free(pathname.s);
	return res;
}

DIR *s_opendir(struct s pathname)
{
	DIR *res;

	res = opendir(pathname.s);
	free(pathname.s);
	return res;
}

int s_getxattr(struct s pathname, const char name[], void *value, size_t size,
	       ssize_t *ret_size)
{
	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	*ret_size = getxattr(pathname.s, name, value, size);
	free(pathname.s);
	return *ret_size >= 0 ? 0 : -1;
}

int s_listxattr(struct s pathname, void *list, size_t size, ssize_t *ret_size)
{
	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	*ret_size = listxattr(pathname.s, list, size);
	free(pathname.s);
	return *ret_size >= 0 ? 0 : -1;
}

int s_setxattr(struct s pathname, const char name[], const void *value, size_t size, int flags)
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = setxattr(pathname.s, name, value, size, flags);
	free(pathname.s);
	return res;
}

int s_removexattr(struct s pathname, const char name[])
{
	int res;

	if (!pathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = removexattr(pathname.s, name);
	free(pathname.s);
	return res;
}

int s_rename(struct s oldpathname, struct s newpathname)
{
	int res;

	if (!oldpathname.s || !newpathname.s) {
		errno = ENOMEM;
		return -1;
	}

	res = rename(oldpathname.s, newpathname.s);
	free(oldpathname.s);
	free(newpathname.s);
	return res;
}

int s_fuse_attr(struct s pathname, struct fuse_attr *fuse_attr_out)
{

	struct stat st;
	int result = TEST_FAILURE;

	TESTSYSCALL(s_stat(pathname, &st));

	fuse_attr_out->ino = st.st_ino;
	fuse_attr_out->mode = st.st_mode;
	fuse_attr_out->nlink = st.st_nlink;
	fuse_attr_out->uid = st.st_uid;
	fuse_attr_out->gid = st.st_gid;
	fuse_attr_out->rdev = st.st_rdev;
	fuse_attr_out->size = st.st_size;
	fuse_attr_out->blksize = st.st_blksize;
	fuse_attr_out->blocks = st.st_blocks;
	fuse_attr_out->atime = st.st_atime;
	fuse_attr_out->mtime = st.st_mtime;
	fuse_attr_out->ctime = st.st_ctime;
	fuse_attr_out->atimensec = UINT32_MAX;
	fuse_attr_out->mtimensec = UINT32_MAX;
	fuse_attr_out->ctimensec = UINT32_MAX;

	result = TEST_SUCCESS;
out:
	return result;
}

struct s tracing_folder(void)
{
	struct s trace = {0};
	FILE *mounts = NULL;
	char *line = NULL;
	size_t size = 0;

	TEST(mounts = fopen("/proc/mounts", "re"), mounts);
	while (getline(&line, &size, mounts) != -1) {
		if (!s_cmp(s_word(sn(line, line + size), ' ', 2),
			   s("tracefs"))) {
			trace = s_word(sn(line, line + size), ' ', 1);
			break;
		}

		if (!s_cmp(s_word(sn(line, line + size), ' ', 2), s("debugfs")))
			trace = s_path(s_word(sn(line, line + size), ' ', 1),
				       s("tracing"));
	}

out:
	free(line);
	fclose(mounts);
	return trace;
}

int tracing_on(void)
{
	int result = TEST_FAILURE;
	int tracing_on = -1;

	TEST(tracing_on = s_open(s_path(tracing_folder(), s("tracing_on")),
				 O_WRONLY | O_CLOEXEC),
	     tracing_on != -1);
	TESTEQUAL(write(tracing_on, "1", 1), 1);
	result = TEST_SUCCESS;
out:
	close(tracing_on);
	return result;
}

char *concat_file_name(const char *dir, const char *file)
{
	char full_name[FILENAME_MAX] = "";

	if (snprintf(full_name, ARRAY_SIZE(full_name), "%s/%s", dir, file) < 0)
		return NULL;
	return strdup(full_name);
}

char *setup_mount_dir(const char *name)
{
	struct stat st;
	char *current_dir = getcwd(NULL, 0);
	char *mount_dir = concat_file_name(current_dir, name);

	free(current_dir);
	if (stat(mount_dir, &st) == 0) {
		if (S_ISDIR(st.st_mode))
			return mount_dir;

		ksft_print_msg("%s is a file, not a dir.\n", mount_dir);
		return NULL;
	}

	if (mkdir(mount_dir, 0777)) {
		ksft_print_msg("Can't create mount dir.");
		return NULL;
	}

	return mount_dir;
}

int delete_dir_tree(const char *dir_path, bool remove_root)
{
	DIR *dir = NULL;
	struct dirent *dp;
	int result = 0;

	dir = opendir(dir_path);
	if (!dir) {
		result = -errno;
		goto out;
	}

	while ((dp = readdir(dir))) {
		char *full_path;

		if (!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
			continue;

		full_path = concat_file_name(dir_path, dp->d_name);
		if (dp->d_type == DT_DIR)
			result = delete_dir_tree(full_path, true);
		else
			result = unlink(full_path);
		free(full_path);
		if (result)
			goto out;
	}

out:
	if (dir)
		closedir(dir);
	if (!result && remove_root)
		rmdir(dir_path);
	return result;
}

static int mount_fuse_maybe_init(const char *mount_dir, const char *bpf_name, int dir_fd,
			     int *fuse_dev_ptr, bool init)
{
	int result = TEST_FAILURE;
	int fuse_dev = -1;
	char options[FILENAME_MAX];
	uint8_t bytes_in[FUSE_MIN_READ_BUFFER];
	uint8_t bytes_out[FUSE_MIN_READ_BUFFER];

	DECL_FUSE_IN(init);

	TEST(fuse_dev = open("/dev/fuse", O_RDWR | O_CLOEXEC), fuse_dev != -1);
	snprintf(options, FILENAME_MAX, "fd=%d,user_id=0,group_id=0,rootmode=0040000",
		 fuse_dev);
	if (bpf_name != NULL)
		snprintf(options + strlen(options),
			 sizeof(options) - strlen(options),
			 ",root_bpf=%s", bpf_name);
	if (dir_fd != -1)
		snprintf(options + strlen(options),
			 sizeof(options) - strlen(options),
			 ",root_dir=%d", dir_fd);
	TESTSYSCALL(mount("ABC", mount_dir, "fuse", 0, options));

	if (init) {
		TESTFUSEIN(FUSE_INIT, init_in);
		TESTEQUAL(init_in->major, FUSE_KERNEL_VERSION);
		TESTEQUAL(init_in->minor, FUSE_KERNEL_MINOR_VERSION);
		TESTFUSEOUT1(fuse_init_out, ((struct fuse_init_out) {
			.major = FUSE_KERNEL_VERSION,
			.minor = FUSE_KERNEL_MINOR_VERSION,
			.max_readahead = 4096,
			.flags = 0,
			.max_background = 0,
			.congestion_threshold = 0,
			.max_write = 4096,
			.time_gran = 1000,
			.max_pages = 12,
			.map_alignment = 4096,
		}));
	}

	*fuse_dev_ptr = fuse_dev;
	fuse_dev = -1;
	result = TEST_SUCCESS;
out:
	close(fuse_dev);
	return result;
}

int mount_fuse(const char *mount_dir, const char * bpf_name, int dir_fd, int *fuse_dev_ptr)
{
	return mount_fuse_maybe_init(mount_dir, bpf_name, dir_fd, fuse_dev_ptr,
				     true);
}

int mount_fuse_no_init(const char *mount_dir, const char * bpf_name, int dir_fd,
		       int *fuse_dev_ptr)
{
	return mount_fuse_maybe_init(mount_dir, bpf_name, dir_fd, fuse_dev_ptr,
				     false);
}

