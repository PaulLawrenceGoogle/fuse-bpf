// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2021 Google LLC

#include "vmlinux.h"
#include <linux/errno.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include <stdbool.h>

#include "bpf_common.h"

char _license[] SEC("license") = "GPL";

#if 0
inline __always_inline int local_strcmp(const char *a, const char *b)
{
	int i;

	for (i = 0; i < __builtin_strlen(b) + 1; ++i)
		if (a[i] != b[i])
			return -1;
	return 0;
}


/* This is a macro to enforce inlining. Without it, the compiler will do the wrong thing for bpf */
#define strcmp_check(a, b, end_b) \
		(((b) + __builtin_strlen(a) + 1 > (end_b)) ? -1 : local_strcmp((b), (a)))
#endif

//trace ops

BPF_STRUCT_OPS(uint32_t, trace_access_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_access_in *in)
{
	bpf_printk("Access: %d", meta->nodeid);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_getattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getattr_in *in)
{
	bpf_printk("Get Attr %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_setattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_setattr_in *in)
{
	bpf_printk("Set Attr %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_opendir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	bpf_printk("Open Dir: %d", meta->nodeid);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_readdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("Read Dir: fh: %lu", in->fh, in->offset);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_lookup_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 1);
	bpf_printk("Lookup: %lx %s", meta->nodeid, name_buf);
	if (meta->nodeid == 1)
		return BPF_FUSE_USER_PREFILTER;
	else
		return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_mknod_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_mknod_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("mknod %s %x %x", name_buf,  in->rdev | in->mode, in->umask);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_mkdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("mkdir: %s %x %x", name_buf, in->mode, in->umask);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_rmdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("rmdir: %s", name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_rename_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_rename_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	struct bpf_dynptr old_name_ptr;
	struct bpf_dynptr new_name_ptr;
	char old_name_buf[255];
	//char new_name_buf[255];

	bpf_fuse_get_ro_dynptr(old_name, &old_name_ptr);
	//bpf_fuse_get_ro_dynptr(new_name, &new_name_ptr);
	bpf_dynptr_read(old_name_buf, 255, &old_name_ptr, 0, 0);
	//bpf_dynptr_read(new_name_buf, 255, &new_name_ptr, 0, 0);
	bpf_printk("rename from %s", old_name_buf);
	//bpf_printk("rename to %s", new_name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_rename2_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_rename2_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	struct bpf_dynptr old_name_ptr;
	//struct bpf_dynptr new_name_ptr;
	char old_name_buf[255];
	//char new_name_buf[255];

	bpf_fuse_get_ro_dynptr(old_name, &old_name_ptr);
	//bpf_fuse_get_ro_dynptr(new_name, &new_name_ptr);
	bpf_dynptr_read(old_name_buf, 255, &old_name_ptr, 0, 0);
	//bpf_dynptr_read(new_name_buf, 255, &new_name_ptr, 0, 0);
	bpf_printk("rename(%x) from %s", in->flags, old_name_buf);
	//bpf_printk("rename to %s", new_name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_unlink_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("unlink: %s", name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_link_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_link_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char dst_name[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(dst_name, 255, &name_ptr, 0, 0);
	bpf_printk("link: %d %s", in->oldnodeid, dst_name);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_symlink_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name, struct fuse_buffer *path)
{
	struct bpf_dynptr name_ptr;
	//struct bpf_dynptr path_ptr;
	char link_name[255];
	//char link_path[4096];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	//bpf_fuse_get_ro_dynptr(path, &path_ptr);
	bpf_dynptr_read(link_name, 255, &name_ptr, 0, 0);
	//bpf_dynptr_read(link_path, 4096, &path_ptr, 0, 0);

	bpf_printk("symlink from %s", link_name);
	//bpf_printk("symlink to %s", link_path);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_get_link_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char link_name[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(link_name, 255, &name_ptr, 0, 0);
	bpf_printk("readlink from %s", link_name);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_release_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	bpf_printk("Release: %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_releasedir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	bpf_printk("Release Dir: %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_create_open_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_create_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("Create %s", name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_open_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	bpf_printk("Open: %d", meta->nodeid);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_read_iter_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("Read: fh: %lu, offset %lu, size %lu",
			   in->fh, in->offset, in->size);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_write_iter_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_write_in *in)
{
	bpf_printk("Write: fh: %lu, offset %lu, size %lu",
			   in->fh, in->offset, in->size);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_flush_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_flush_in *in)
{
	bpf_printk("flush %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_file_fallocate_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_fallocate_in *in)
{
	bpf_printk("fallocate %d %lu", in->fh, in->length);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_getxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("getxattr %d %s", meta->nodeid, name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_listxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in)
{
	bpf_printk("listxattr %d %d", meta->nodeid, in->size);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_setxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_setxattr_in *in, struct fuse_buffer *name,
					struct fuse_buffer *value)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("setxattr %d %s", meta->nodeid, name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_removexattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("removexattr %d %s", meta->nodeid, name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_statfs_prefilter, const struct bpf_fuse_meta_info *meta)
{
	bpf_printk("statfs %d", meta->nodeid);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_lseek_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_lseek_in *in)
{
	bpf_printk("lseek type:%d, offset:%lld", in->whence, in->offset);
	return BPF_FUSE_CONTINUE;
}

// readdir_test_ops
BPF_STRUCT_OPS(uint32_t, readdir_redact_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("readdir %d", in->fh);
	return BPF_FUSE_POSTFILTER;
}

BPF_STRUCT_OPS(uint32_t, readdir_redact_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_out *out, struct fuse_buffer *buffer)
{
	bpf_printk("readdir postfilter %x", in->fh);
	return BPF_FUSE_USER_POSTFILTER;
}

// test operations

BPF_STRUCT_OPS(uint32_t, test_lookup_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;
	bool backing = false;
	int ret;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);

	/* bpf_dynptr_slice will only return a pointer if the dynptr is long enough */
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 8);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 8, "partial") == 0)
			backing = true;
		goto print;
	}
	
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 6);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 6, "file1") == 0)
			backing = true;
		if (bpf_strncmp(name_buf, 6, "file2") == 0)
			backing = true;
		goto print;
	}

	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 5);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 5, "dir2") == 0)
			backing = true;
		if (bpf_strncmp(name_buf, 5, "real") == 0)
			backing = true;
		goto print;
	}

	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 4);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 4, "dir") == 0)
			backing = true;
		goto print;
	}
print:
	if (name_buf)
		bpf_printk("lookup %s %d", name_buf, backing);
	else
		bpf_printk("lookup [name length under 3] %d", backing);
	return backing ? BPF_FUSE_POSTFILTER : BPF_FUSE_USER;
}

BPF_STRUCT_OPS(uint32_t, test_lookup_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);

	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 8);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 8, "partial") == 0)
			out->nodeid = 6;
		goto print;
	}
	
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 5);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 5, "real") == 0)
			out->nodeid = 5;
		goto print;
	}
print:
	if (name_buf)
		bpf_printk("post-lookup %s %d", name_buf, out->nodeid);
	else
		bpf_printk("post-lookup [name length under 4] %d", out->nodeid);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, test_open_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	int backing = BPF_FUSE_USER;

	switch (meta->nodeid) {
	case 5:
		backing = BPF_FUSE_CONTINUE;
		bpf_printk("Setting BPF_FUSE_CONTINUE:%d", BPF_FUSE_CONTINUE);
		break;

	case 6:
		backing = BPF_FUSE_POSTFILTER;
		bpf_printk("Setting BPF_FUSE_CONTINUE:%d", BPF_FUSE_POSTFILTER);
		break;

	default:
		bpf_printk("Setting NOTHING %d", BPF_FUSE_USER);
		break;
	}

	bpf_printk("open: %d %d", meta->nodeid, backing);
	return backing;
}

BPF_STRUCT_OPS(uint32_t, test_open_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	bpf_printk("open postfilter");
	return BPF_FUSE_USER_POSTFILTER;
}

BPF_STRUCT_OPS(uint32_t, test_read_iter_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("read %llu %llu", in->fh, in->offset);
	if (in->fh == 1 && in->offset == 0)
		return BPF_FUSE_USER;
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, test_getattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getattr_in *in)
{
	/* real and partial use backing file */
	int backing = BPF_FUSE_USER;

	switch (meta->nodeid) {
	case 1:
	case 5:
	case 6:
	/*
	 * TODO: Find better solution
	 * Add 100 to stop clang compiling to jump table which bpf hates
	 */
	case 100:
		backing = BPF_FUSE_CONTINUE;
		break;
	}

	bpf_printk("getattr %d %d", meta->nodeid, backing);
	return backing;
}

BPF_STRUCT_OPS(uint32_t, test_setattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_setattr_in *in)
{
	/* real and partial use backing file */
	int backing = BPF_FUSE_USER;

	switch (meta->nodeid) {
	case 1:
	case 5:
	case 6:
	/* TODO See above */
	case 100:
		backing = BPF_FUSE_CONTINUE;
		break;
	}

	bpf_printk("setattr %d %d", meta->nodeid, backing);
	return backing;
}

BPF_STRUCT_OPS(uint32_t, test_opendir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	int backing = BPF_FUSE_USER;

	switch (meta->nodeid) {
	case 1:
		backing = BPF_FUSE_POSTFILTER;
		break;
	}
	bpf_printk("opendir %d %d", meta->nodeid, backing);
	return backing;
}

BPF_STRUCT_OPS(uint32_t, test_opendir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	out->fh = 2;
	bpf_printk("opendir postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, test_readdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	int backing = BPF_FUSE_USER;

	if (in->fh == 2)
		backing = BPF_FUSE_POSTFILTER;

	bpf_printk("readdir %d %d", in->fh, backing);
	return backing;
}

BPF_STRUCT_OPS(uint32_t, test_readdir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_out *out, struct fuse_buffer *buffer)
{
	int backing = BPF_FUSE_CONTINUE;

	if (in->fh == 2)
		backing = BPF_FUSE_USER_POSTFILTER;

	bpf_printk("readdir postfilter %d %d", in->fh, backing);
	return backing;
}

// test_hidden

BPF_STRUCT_OPS(uint32_t, hidden_lookup_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;
	bool backing = false;
	int ret;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);

	/* bpf_dynptr_slice will only return a pointer if the dynptr is long enough */
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 5);
	if (name_buf)
		bpf_printk("Lookup: %s", name_buf);
	else
		bpf_printk("lookup [name length under 4]");
	if (name_buf) {
		if (bpf_strncmp(name_buf, 5, "show") == 0)
			return BPF_FUSE_CONTINUE;
		if (bpf_strncmp(name_buf, 5, "hide") == 0)
			return -ENOENT;
	}

	return BPF_FUSE_CONTINUE;
}

// test_error

BPF_STRUCT_OPS(uint32_t, error_mkdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name)
{
	bpf_printk("mkdir");

	return BPF_FUSE_POSTFILTER;
}

BPF_STRUCT_OPS(uint32_t, error_mkdir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_mkdir_in *in, const struct fuse_buffer *name)
{
	bpf_printk("mkdir postfilter");

	if (meta->error_in == -EEXIST)
		return -EPERM;
	return 0;
}

BPF_STRUCT_OPS(uint32_t, error_lookup_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;
	bool backing = false;
	int ret;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);

	/* bpf_dynptr_slice will only return a pointer if the dynptr is long enough */
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 1);
	bpf_printk("lookup prefilter %s", name);
	return BPF_FUSE_POSTFILTER;
}

BPF_STRUCT_OPS(uint32_t, error_lookup_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	struct bpf_dynptr name_ptr;
	char *name_buf;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 13);
	if (name_buf)
		bpf_printk("post-lookup %s %d", name_buf, out->nodeid);
	else
		bpf_printk("post-lookup [name length under 13] %d", out->nodeid);
	if (name_buf) {
		if (bpf_strncmp(name_buf, 13, "doesnotexist") == 0) {
			bpf_printk("lookup postfilter doesnotexist");
			return BPF_FUSE_USER_POSTFILTER;
		}
	}
	
	return 0;
}

// test readdirplus

BPF_STRUCT_OPS(uint32_t, readdirplus_readdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	return BPF_FUSE_USER;
}

// Test passthrough

// Reuse error_lookup_prefilter

BPF_STRUCT_OPS(uint32_t, passthrough_lookup_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	struct bpf_dynptr name_ptr;
	struct bpf_dynptr entries_ptr;
	char *name_buf;
	struct fuse_bpf_entry_out entry;

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 1);
	if (name_buf)
		bpf_printk("post-lookup %s %d", name_buf, out->nodeid);
	else
		bpf_printk("post-lookup [name length under 1???] %d", out->nodeid);
	bpf_fuse_get_rw_dynptr(entries, &entries_ptr, sizeof(entry), false);
	entry = (struct fuse_bpf_entry_out) {
			.entry_type = FUSE_ENTRY_REMOVE_BPF,
		};
	bpf_dynptr_write(&entries_ptr, 0, &entry, sizeof(entry), 0);
	
	return BPF_FUSE_USER_POSTFILTER;
}

// lookup_postfilter_ops

//reuse error_lookup_prefilter

BPF_STRUCT_OPS(uint32_t, test_bpf_lookup_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	return BPF_FUSE_USER_POSTFILTER;
}

SEC(".struct_ops")
struct fuse_ops trace_ops = {
	.open_prefilter = (void *)trace_open_prefilter,
	.opendir_prefilter = (void *)trace_opendir_prefilter,
	.create_open_prefilter = (void *)trace_create_open_prefilter,
	.release_prefilter = (void *)trace_release_prefilter,
	.releasedir_prefilter = (void *)trace_releasedir_prefilter,
	.flush_prefilter = (void *)trace_flush_prefilter,
	.lseek_prefilter = (void *)trace_lseek_prefilter,
	//.copy_file_range_prefilter = (void *)trace_copy_file_range_prefilter,
	//.fsync_prefilter = (void *)trace_fsync_prefilter,
	//.dir_fsync_prefilter = (void *)trace_dir_fsync_prefilter,
	.getxattr_prefilter = (void *)trace_getxattr_prefilter,
	.listxattr_prefilter = (void *)trace_listxattr_prefilter,
	.setxattr_prefilter = (void *)trace_setxattr_prefilter,
	.removexattr_prefilter = (void *)trace_removexattr_prefilter,
	.read_iter_prefilter = (void *)trace_read_iter_prefilter,
	.write_iter_prefilter = (void *)trace_write_iter_prefilter,
	.file_fallocate_prefilter = (void *)trace_file_fallocate_prefilter,
	.lookup_prefilter = (void *)trace_lookup_prefilter,
	.mknod_prefilter = (void *)trace_mknod_prefilter,
	.mkdir_prefilter = (void *)trace_mkdir_prefilter,
	.rmdir_prefilter = (void *)trace_rmdir_prefilter,
	.rename2_prefilter = (void *)trace_rename2_prefilter,
	.rename_prefilter = (void *)trace_rename_prefilter,
	.unlink_prefilter = (void *)trace_unlink_prefilter,
	.link_prefilter = (void *)trace_link_prefilter,
	.getattr_prefilter = (void *)trace_getattr_prefilter,
	.setattr_prefilter = (void *)trace_setattr_prefilter,
	.statfs_prefilter = (void *)trace_statfs_prefilter,
	.get_link_prefilter = (void *)trace_get_link_prefilter,
	.symlink_prefilter = (void *)trace_symlink_prefilter,
	.readdir_prefilter = (void *)trace_readdir_prefilter,
	.access_prefilter = (void *)trace_access_prefilter,
	.name = "trace_ops",
};

SEC(".struct_ops")
struct fuse_ops test_trace_ops = {
	.open_prefilter = (void *)test_open_prefilter,
	.open_postfilter = (void *)test_open_postfilter,
	.opendir_prefilter = (void *)test_opendir_prefilter,
	.opendir_postfilter = (void *)test_opendir_postfilter,
	.create_open_prefilter = (void *)trace_create_open_prefilter,
	.release_prefilter = (void *)trace_release_prefilter,
	.releasedir_prefilter = (void *)trace_releasedir_prefilter,
	.flush_prefilter = (void *)trace_flush_prefilter,
	.lseek_prefilter = (void *)trace_lseek_prefilter,
	//.copy_file_range_prefilter = (void *)trace_copy_file_range_prefilter,
	//.fsync_prefilter = (void *)trace_fsync_prefilter,
	//.dir_fsync_prefilter = (void *)trace_dir_fsync_prefilter,
	.getxattr_prefilter = (void *)trace_getxattr_prefilter,
	.listxattr_prefilter = (void *)trace_listxattr_prefilter,
	.setxattr_prefilter = (void *)trace_setxattr_prefilter,
	.removexattr_prefilter = (void *)trace_removexattr_prefilter,
	.read_iter_prefilter = (void *)test_read_iter_prefilter,
	.write_iter_prefilter = (void *)trace_write_iter_prefilter,
	.file_fallocate_prefilter = (void *)trace_file_fallocate_prefilter,
	.lookup_prefilter = (void *)test_lookup_prefilter,
	.lookup_postfilter = (void *)test_lookup_postfilter,
	.mknod_prefilter = (void *)trace_mknod_prefilter,
	.mkdir_prefilter = (void *)trace_mkdir_prefilter,
	.rmdir_prefilter = (void *)trace_rmdir_prefilter,
	.rename2_prefilter = (void *)trace_rename2_prefilter,
	.rename_prefilter = (void *)trace_rename_prefilter,
	.unlink_prefilter = (void *)trace_unlink_prefilter,
	.link_prefilter = (void *)trace_link_prefilter,
	.getattr_prefilter = (void *)test_getattr_prefilter,
	.setattr_prefilter = (void *)test_setattr_prefilter,
	.statfs_prefilter = (void *)trace_statfs_prefilter,
	.get_link_prefilter = (void *)trace_get_link_prefilter,
	.symlink_prefilter = (void *)trace_symlink_prefilter,
	.readdir_prefilter = (void *)test_readdir_prefilter,
	.readdir_postfilter = (void *)test_readdir_postfilter,
	.access_prefilter = (void *)trace_access_prefilter,
	.name = "test_trace_ops",
};

SEC(".struct_ops")
struct fuse_ops readdir_redact_ops = {
	.readdir_prefilter = (void *)readdir_redact_prefilter,
	.readdir_postfilter = (void *)readdir_redact_postfilter,
	.name = "readdir_redact",
};

SEC(".struct_ops")
struct fuse_ops test_hidden_ops = {
	.lookup_prefilter = (void *)hidden_lookup_prefilter,
	.access_prefilter = (void *)trace_access_prefilter,
	.create_open_prefilter = (void *)trace_create_open_prefilter,
	.name = "test_hidden",
};

SEC(".struct_ops")
struct fuse_ops test_error_ops = {
	.lookup_prefilter = (void *)error_lookup_prefilter,
	.lookup_postfilter = (void *)error_lookup_postfilter,
	.mkdir_prefilter = (void *)error_mkdir_prefilter,
	.mkdir_postfilter = (void *)error_mkdir_postfilter,
	.name = "test_error",
};

SEC(".struct_ops")
struct fuse_ops readdir_plus_ops = {
	.readdir_prefilter = (void *)readdirplus_readdir_prefilter,
	.name = "readdir_plus",
};

SEC(".struct_ops")
struct fuse_ops passthrough_ops = {
	.lookup_prefilter = (void *)error_lookup_prefilter,
	.lookup_postfilter = (void *)passthrough_lookup_postfilter,
	.name = "passthrough",
};

SEC(".struct_ops")
struct fuse_ops lookup_postfilter_ops = {
	.lookup_prefilter = (void *)error_lookup_prefilter,
	.lookup_postfilter = (void *)test_bpf_lookup_postfilter,
	.name = "lookup_post",
};

#if 0
//TODO: Figure out what to do with these
SEC("test_verify")

int verify_test(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_MKDIR | FUSE_PREFILTER)) {
		const char *start;
		const char *end;
		const struct fuse_mkdir_in *in;

		start = (void *)(long) fa->in_args[0].value;
		end = (void *)(long) fa->in_args[0].end_offset;
		if (start + sizeof(*in) <= end) {
			in = (struct fuse_mkdir_in *)(start);
			bpf_printk("test1: %d %d", in->mode, in->umask);
		}

		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail")

int verify_fail_test(struct __bpf_fuse_args *fa)
{
	struct t {
		uint32_t a;
		uint32_t b;
		char d[];
	};
	if (fa->opcode == (FUSE_MKDIR | FUSE_PREFILTER)) {
		const char *start;
		const char *end;
		const struct t *c;

		start = (void *)(long) fa->in_args[0].value;
		end = (void *)(long) fa->in_args[0].end_offset;
		if (start + sizeof(struct t) <= end) {
			c = (struct t *)start;
			bpf_printk("test1: %d %d %d", c->a, c->b, c->d[0]);
		}
		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail2")

int verify_fail_test2(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_MKDIR | FUSE_PREFILTER)) {
		const char *start;
		const char *end;
		struct fuse_mkdir_in *c;

		start = (void *)(long) fa->in_args[0].value;
		end = (void *)(long) fa->in_args[1].end_offset;
		if (start + sizeof(*c) <= end) {
			c = (struct fuse_mkdir_in *)start;
			bpf_printk("test1: %d %d", c->mode, c->umask);
		}
		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail3")
/* Cannot write directly to fa */
int verify_fail_test3(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_LOOKUP | FUSE_POSTFILTER)) {
		const char *name = (void *)(long)fa->in_args[0].value;
		const char *end = (void *)(long)fa->in_args[0].end_offset;
		struct fuse_entry_out *feo = fa_verify_out(fa, 0, sizeof(*feo));

		if (!feo)
			return -1;

		if (strcmp_check("real", name, end) == 0)
			feo->nodeid = 5;
		else if (strcmp_check("partial", name, end) == 0)
			feo->nodeid = 6;

		bpf_printk("post-lookup %s %d", name, feo->nodeid);
		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail4")
/* Cannot write outside of requested area */
int verify_fail_test4(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_LOOKUP | FUSE_POSTFILTER)) {
		const char *name = (void *)(long)fa->in_args[0].value;
		const char *end = (void *)(long)fa->in_args[0].end_offset;
		struct fuse_entry_out *feo = bpf_make_writable_out(fa, 0, fa->out_args[0].value,
								   1, true);

		if (!feo)
			return -1;

		if (strcmp_check("real", name, end) == 0)
			feo->nodeid = 5;
		else if (strcmp_check("partial", name, end) == 0)
			feo->nodeid = 6;

		bpf_printk("post-lookup %s %d", name, feo->nodeid);
		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail5")
/* Cannot use old verification after requesting writable */
int verify_fail_test5(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_LOOKUP | FUSE_POSTFILTER)) {
		struct fuse_entry_out *feo;
		struct fuse_entry_out *feo_w;

		feo = fa_verify_out(fa, 0, sizeof(*feo));
		if (!feo)
			return -1;

		feo_w = bpf_make_writable_out(fa, 0, fa->out_args[0].value, sizeof(*feo_w), true);
		bpf_printk("post-lookup %d", feo->nodeid);
		if (!feo_w)
			return -1;

		feo_w->nodeid = 5;

		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify5")
/* Can use new verification after requesting writable */
int verify_pass_test5(struct __bpf_fuse_args *fa)
{
	if (fa->opcode == (FUSE_LOOKUP | FUSE_POSTFILTER)) {
		struct fuse_entry_out *feo;
		struct fuse_entry_out *feo_w;

		feo = fa_verify_out(fa, 0, sizeof(*feo));
		if (!feo)
			return -1;

		bpf_printk("post-lookup %d", feo->nodeid);

		feo_w = bpf_make_writable_out(fa, 0, fa->out_args[0].value, sizeof(*feo_w), true);

		feo = fa_verify_out(fa, 0, sizeof(*feo));
		if (feo)
			bpf_printk("post-lookup %d", feo->nodeid);
		if (!feo_w)
			return -1;

		feo_w->nodeid = 5;

		return BPF_FUSE_CONTINUE;
	}
	return BPF_FUSE_CONTINUE;
}

SEC("test_verify_fail6")
/* Reading context from a nonsense offset is not allowed */
int verify_pass_test6(struct __bpf_fuse_args *fa)
{
	char *nonsense = (char *)fa;

	bpf_printk("post-lookup %d", nonsense[1]);

	return BPF_FUSE_CONTINUE;
}
#endif
