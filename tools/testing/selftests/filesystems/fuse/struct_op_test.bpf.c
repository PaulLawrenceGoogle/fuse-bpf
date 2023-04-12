// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (c) 2021 Google LLC

#include "vmlinux.h"
//#include <uapi/linux/bpf.h>
#include <linux/errno.h>
#include <linux/types.h>
//#include <linux/fuse.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>
#include "bpf_common.h"

char _license[] SEC("license") = "GPL";

#define BPF_STRUCT_OPS(type, name, args...)					\
SEC("struct_ops/"#name)								\
type BPF_PROG(name, ##args)

/*
struct test_struct {
	uint32_t a;
	uint32_t b;
};


*/
//struct fuse_buffer;
#define BPF_FUSE_CONTINUE		0
/*struct fuse_ops {
	uint32_t (*test_func)(void);
	uint32_t (*test_func2)(struct test_struct *a);
	uint32_t (*test_func3)(struct fuse_name *ptr);
	//u32 (*open_prefilter)(struct bpf_fuse_hidden_info meh, struct bpf_fuse_meta_info header, struct fuse_open_in foi);
	//u32 (*open_postfilter)(struct bpf_fuse_hidden_info meh, struct bpf_fuse_meta_info header, const struct fuse_open_in foi, struct fuse_open_out foo);
	char name[BPF_FUSE_NAME_MAX];
};
*/
extern uint32_t bpf_fuse_return_len(struct fuse_buffer *ptr) __ksym;
extern void bpf_fuse_get_rw_dynptr(struct fuse_buffer *buffer, struct bpf_dynptr *dynptr, u64 size, bool copy) __ksym;
extern void bpf_fuse_get_ro_dynptr(const struct fuse_buffer *buffer, struct bpf_dynptr *dynptr) __ksym;

//extern struct bpf_key *bpf_lookup_user_key(__u32 serial, __u64 flags) __ksym;
//extern struct bpf_key *bpf_lookup_system_key(__u64 id) __ksym;
//extern void bpf_key_put(struct bpf_key *key) __ksym;
//extern int bpf_verify_pkcs7_signature(struct bpf_dynptr *data_ptr,
//				      struct bpf_dynptr *sig_ptr,
//				      struct bpf_key *trusted_keyring) __ksym;

BPF_STRUCT_OPS(uint32_t, test_func, const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name)
{
	int res = 0;
	struct bpf_dynptr name_ptr;
	char *name_buf;
	//char dummy[7] = {};

	bpf_fuse_get_ro_dynptr(name, &name_ptr);
	name_buf = bpf_dynptr_slice(&name_ptr, 0, NULL, 4);
	bpf_printk("Hello test print");
	if (!name_buf)
		return -ENOMEM;
	if (!bpf_strncmp(name_buf, 4, "test"))
		return 42;	

	//if (bpf_fuse_namecmp(name, "test", 4) == 0)
	//	return 42;

	return res;
}

SEC(".struct_ops")
struct fuse_ops test_ops = {
	.mkdir_prefilter = (void *)test_func,
	.name = "test",
};

BPF_STRUCT_OPS(uint32_t, open_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	bpf_printk("open_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, open_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	bpf_printk("open_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, opendir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in)
{
	bpf_printk("opendir_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, opendir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out)
{
	bpf_printk("opendir_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, create_open_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_create_in *in, struct fuse_buffer *name)
{
	bpf_printk("create_open_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, create_open_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_create_in *in, const struct fuse_buffer *name,
				struct fuse_entry_out *entry_out, struct fuse_open_out *out)
{
	bpf_printk("create_open_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, release_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	bpf_printk("release_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, release_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in)
{
	bpf_printk("release_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, releasedir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in)
{
	bpf_printk("releasedir_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, releasedir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in)
{
	bpf_printk("releasedir_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, flush_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_flush_in *in)
{
	bpf_printk("flush_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, flush_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_flush_in *in)
{
	bpf_printk("flush_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, lseek_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_lseek_in *in)
{
	bpf_printk("lseek_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, lseek_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_lseek_in *in,
				struct fuse_lseek_out *out)
{
	bpf_printk("lseek_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, copy_file_range_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_copy_file_range_in *in)
{
	bpf_printk("copy_file_range_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, copy_file_range_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_copy_file_range_in *in,
				struct fuse_write_out *out)
{
	bpf_printk("copy_file_range_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, fsync_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in)
{
	bpf_printk("fsync_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, fsync_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in)
{
	bpf_printk("fsync_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, dir_fsync_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in)
{
	bpf_printk("dir_fsync_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, dir_fsync_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in)
{
	bpf_printk("dir_fsync_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, getxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in, struct fuse_buffer *name)
{
	bpf_printk("getxattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, getxattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in, const struct fuse_buffer *name,
				struct fuse_buffer *value, struct fuse_getxattr_out *out)
{
	bpf_printk("getxattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, listxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in)
{
	bpf_printk("listxattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, listxattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in,
				struct fuse_buffer *value, struct fuse_getxattr_out *out)
{
	bpf_printk("listxattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, setxattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_setxattr_in *in, struct fuse_buffer *name,
					struct fuse_buffer *value)
{
	bpf_printk("setxattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, setxattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_setxattr_in *in, const struct fuse_buffer *name,
					const struct fuse_buffer *value)
{
	bpf_printk("setxattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, removexattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	bpf_printk("removexattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, removexattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	bpf_printk("removexattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, read_iter_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("read_iter_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, read_iter_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_iter_out *out)
{
	bpf_printk("read_iter_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, write_iter_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_write_in *in)
{
	bpf_printk("write_iter_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, write_iter_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_write_in *in,
				struct fuse_write_iter_out *out)
{
	bpf_printk("write_iter_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, file_fallocate_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_fallocate_in *in)
{
	bpf_printk("file_fallocate_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, file_fallocate_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_fallocate_in *in)
{
	bpf_printk("file_fallocate_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, lookup_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	bpf_printk("lookup_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, lookup_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries)
{
	bpf_printk("lookup_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, mknod_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_mknod_in *in, struct fuse_buffer *name)
{
	bpf_printk("mknod_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, mknod_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_mknod_in *in, const struct fuse_buffer *name)
{
	bpf_printk("mknod_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, mkdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name)
{
	bpf_printk("mkdir_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, mkdir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_mkdir_in *in, const struct fuse_buffer *name)
{
	bpf_printk("mkdir_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rmdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	bpf_printk("rmdir_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rmdir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	bpf_printk("rmdir_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rename2_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_rename2_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	bpf_printk("rename2_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rename2_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename2_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name)
{
	bpf_printk("rename2_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rename_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_rename_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name)
{
	bpf_printk("rename_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, rename_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name)
{
	bpf_printk("rename_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, unlink_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	bpf_printk("unlink_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, unlink_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	bpf_printk("unlink_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, link_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_link_in *in, struct fuse_buffer *name)
{
	bpf_printk("link_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, link_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_link_in *in, const struct fuse_buffer *name)
{
	bpf_printk("link_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, getattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_getattr_in *in)
{
	bpf_printk("getattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, getattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_getattr_in *in,
				struct fuse_attr_out *out)
{
	bpf_printk("getattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, setattr_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_setattr_in *in)
{
	bpf_printk("setattr_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, setattr_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_setattr_in *in,
				struct fuse_attr_out *out)
{
	bpf_printk("setattr_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, statfs_prefilter, const struct bpf_fuse_meta_info *meta)
{
	bpf_printk("statfs_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, statfs_postfilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_statfs_out *out)
{
	bpf_printk("statfs_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, get_link_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name)
{
	bpf_printk("get_link_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, get_link_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name)
{
	bpf_printk("get_link_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, symlink_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name, struct fuse_buffer *path)
{
	bpf_printk("symlink_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, symlink_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name, const struct fuse_buffer *path)
{
	bpf_printk("symlink_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, readdir_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in)
{
	bpf_printk("readdir_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, readdir_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_out *out, struct fuse_buffer *buffer)
{
	bpf_printk("readdir_postfilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, access_prefilter, const struct bpf_fuse_meta_info *meta,
				struct fuse_access_in *in)
{
	bpf_printk("access_prefilter");
	return BPF_FUSE_CONTINUE;
}

BPF_STRUCT_OPS(uint32_t, access_postfilter, const struct bpf_fuse_meta_info *meta,
				const struct fuse_access_in *in)
{
	bpf_printk("access_postfilter");
	return BPF_FUSE_CONTINUE;
}

SEC(".struct_ops")
struct fuse_ops trace_ops = {
	.open_prefilter = (void *)open_prefilter,
	.open_postfilter = (void *)open_postfilter,

	.opendir_prefilter = (void *)opendir_prefilter,
	.opendir_postfilter = (void *)opendir_postfilter,

	.create_open_prefilter = (void *)create_open_prefilter,
	.create_open_postfilter = (void *)create_open_postfilter,

	.release_prefilter = (void *)release_prefilter,
	.release_postfilter = (void *)release_postfilter,

	.releasedir_prefilter = (void *)releasedir_prefilter,
	.releasedir_postfilter = (void *)releasedir_postfilter,

	.flush_prefilter = (void *)flush_prefilter,
	.flush_postfilter = (void *)flush_postfilter,

	.lseek_prefilter = (void *)lseek_prefilter,
	.lseek_postfilter = (void *)lseek_postfilter,

	.copy_file_range_prefilter = (void *)copy_file_range_prefilter,
	.copy_file_range_postfilter = (void *)copy_file_range_postfilter,

	.fsync_prefilter = (void *)fsync_prefilter,
	.fsync_postfilter = (void *)fsync_postfilter,

	.dir_fsync_prefilter = (void *)dir_fsync_prefilter,
	.dir_fsync_postfilter = (void *)dir_fsync_postfilter,

	.getxattr_prefilter = (void *)getxattr_prefilter,
	.getxattr_postfilter = (void *)getxattr_postfilter,

	.listxattr_prefilter = (void *)listxattr_prefilter,
	.listxattr_postfilter = (void *)listxattr_postfilter,

	.setxattr_prefilter = (void *)setxattr_prefilter,
	.setxattr_postfilter = (void *)setxattr_postfilter,

	.removexattr_prefilter = (void *)removexattr_prefilter,
	.removexattr_postfilter = (void *)removexattr_postfilter,

	.read_iter_prefilter = (void *)read_iter_prefilter,
	.read_iter_postfilter = (void *)read_iter_postfilter,

	.write_iter_prefilter = (void *)write_iter_prefilter,
	.write_iter_postfilter = (void *)write_iter_postfilter,

	.file_fallocate_prefilter = (void *)file_fallocate_prefilter,
	.file_fallocate_postfilter = (void *)file_fallocate_postfilter,

	.lookup_prefilter = (void *)lookup_prefilter,
	.lookup_postfilter = (void *)lookup_postfilter,

	.mknod_prefilter = (void *)mknod_prefilter,
	.mknod_postfilter = (void *)mknod_postfilter,

	.mkdir_prefilter = (void *)mkdir_prefilter,
	.mkdir_postfilter = (void *)mkdir_postfilter,

	.rmdir_prefilter = (void *)rmdir_prefilter,
	.rmdir_postfilter = (void *)rmdir_postfilter,

	.rename2_prefilter = (void *)rename2_prefilter,
	.rename2_postfilter = (void *)rename2_postfilter,

	.rename_prefilter = (void *)rename_prefilter,
	.rename_postfilter = (void *)rename_postfilter,

	.unlink_prefilter = (void *)unlink_prefilter,
	.unlink_postfilter = (void *)unlink_postfilter,

	.link_prefilter = (void *)link_prefilter,
	.link_postfilter = (void *)link_postfilter,

	.getattr_prefilter = (void *)getattr_prefilter,
	.getattr_postfilter = (void *)getattr_postfilter,

	.setattr_prefilter = (void *)setattr_prefilter,
	.setattr_postfilter = (void *)setattr_postfilter,

	.statfs_prefilter = (void *)statfs_prefilter,
	.statfs_postfilter = (void *)statfs_postfilter,

	.get_link_prefilter = (void *)get_link_prefilter,
	.get_link_postfilter = (void *)get_link_postfilter,

	.symlink_prefilter = (void *)symlink_prefilter,
	.symlink_postfilter = (void *)symlink_postfilter,

	.readdir_prefilter = (void *)readdir_prefilter,
	.readdir_postfilter = (void *)readdir_postfilter,

	.access_prefilter = (void *)access_prefilter,
	.access_postfilter = (void *)access_postfilter,

	.name = "trace_pre_ops",
};
