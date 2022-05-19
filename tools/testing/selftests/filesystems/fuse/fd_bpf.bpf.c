// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2021 Google LLC

//#define __EXPORTED_HEADERS__
//#define __KERNEL__

//#include <uapi/linux/bpf.h>
//#include <linux/fuse.h>

#include "vmlinux.h"
#include <linux/errno.h>
#include <linux/types.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

#include "bpf_common.h"

char _license[] SEC("license") = "GPL";

#if 0
struct fuse_bpf_map {
	int map_type;
	int key_size;
	int value_size;
	int max_entries;
};
SEC("dummy")

inline int strcmp(const char *a, const char *b)
{
	int i;

	for (i = 0; i < __builtin_strlen(b) + 1; ++i)
		if (a[i] != b[i])
			return -1;

	return 0;
}

SEC("maps") struct fuse_bpf_map test_map = {
	BPF_MAP_TYPE_ARRAY,
	sizeof(uint32_t),
	sizeof(uint32_t),
	1000,
};

SEC("maps") struct fuse_bpf_map test_map2 = {
	BPF_MAP_TYPE_HASH,
	sizeof(uint32_t),
	sizeof(uint64_t),
	76,
};

SEC("test_daemon")

int trace_daemon(struct __bpf_fuse_args *fa)
{
	uint64_t uid_gid = bpf_get_current_uid_gid();
	uint32_t uid = uid_gid & 0xffffffff;
	uint64_t pid_tgid = bpf_get_current_pid_tgid();
	uint32_t pid = pid_tgid & 0xffffffff;
	uint32_t key = 23;
	uint32_t *pvalue;


	pvalue = bpf_map_lookup_elem(&test_map, &key);
	if (pvalue) {
		uint32_t value = *pvalue;

		bpf_printk("pid %u uid %u value %u", pid, uid, value);
		value++;
		bpf_map_update_elem(&test_map, &key,  &value, BPF_ANY);
	}

	switch (fa->opcode) {
#endif
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
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
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
	bpf_printk("Link: %d %s", in->oldnodeid, dst_name);
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
	bpf_printk("Flush %d", in->fh);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_file_fallocate_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_fallocate_in *in)
{
	bpf_printk("Fallocate %d %lu", in->fh, in->length);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_getxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in, struct fuse_buffer *name)
{
	struct bpf_dynptr name_ptr;
	char name_buf[255];

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	bpf_dynptr_read(name_buf, 255, &name_ptr, 0, 0);
	bpf_printk("Getxattr %d %s", meta->nodeid, name_buf);
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, trace_listxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in)
{
	bpf_printk("Listxattr %d %d", meta->nodeid, in->size);
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
	bpf_printk("Setxattr %d %s", meta->nodeid, name_buf);
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
	//.removexattr_prefilter = (void *)trace_removexattr_prefilter,
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

