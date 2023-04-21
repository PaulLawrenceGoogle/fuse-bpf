/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright 2022 Google LLC.
 */

#ifndef _BPF_FUSE_H
#define _BPF_FUSE_H

#include <linux/types.h>
#include <linux/fuse.h>

struct fuse_buffer {
	void *data;
	unsigned size;
	unsigned alloc_size;
	unsigned max_size;
	int flags;
};

/* These flags are used internally to track information about the fuse buffers.
 * Fuse sets some of the flags in init. The helper functions sets others, depending on what
 * was requested by the bpf program.
 */
// Flags set by FUSE
#define BPF_FUSE_IMMUTABLE	(1 << 0) // Buffer may not be written to
#define BPF_FUSE_VARIABLE_SIZE	(1 << 1) // Buffer length may be changed (growth requires alloc)
#define BPF_FUSE_MUST_ALLOCATE	(1 << 2) // Buffer must be re allocated before allowing writes

// Flags set by helper function
#define BPF_FUSE_MODIFIED	(1 << 3) // The helper function allowed writes to the buffer
#define BPF_FUSE_ALLOCATED	(1 << 4) // The helper function allocated the buffer

extern void *bpf_fuse_get_writeable(struct fuse_buffer *arg, u64 size, bool copy);

/*
 * BPF Fuse Args
 *
 * Used to translate between bpf program parameters and their userspace equivalent calls.
 * Variable sized arguments are held in fuse_buffers. To access these, bpf programs must
 * use kfuncs to access them as dynptrs.
 *
 */

#define FUSE_MAX_ARGS_IN 3
#define FUSE_MAX_ARGS_OUT 2

struct bpf_fuse_arg {
	union {
		void *value;
		struct fuse_buffer *buffer;
	};
	unsigned size;
	bool is_buffer;
};

struct bpf_fuse_meta_info {
	uint64_t nodeid;
	uint32_t opcode;
	uint32_t error_in;
	uint32_t error_out; // TODO: struct_op programs may set this to alter reported error code
};

struct bpf_fuse_args {
	struct bpf_fuse_meta_info info;
	uint32_t in_numargs;
	uint32_t out_numargs;
	uint32_t flags;
	uint32_t ret;
	struct bpf_fuse_arg in_args[FUSE_MAX_ARGS_IN];
	struct bpf_fuse_arg out_args[FUSE_MAX_ARGS_OUT];
};

// Mirrors for struct fuse_args flags
#define FUSE_BPF_FORCE (1 << 0)
#define FUSE_BPF_OUT_ARGVAR (1 << 6)
#define FUSE_BPF_IS_LOOKUP (1 << 11)

static inline void *bpf_fuse_arg_value(const struct bpf_fuse_arg *arg)
{
	return arg->is_buffer ? arg->buffer : arg->value;
}

static inline unsigned bpf_fuse_arg_size(const struct bpf_fuse_arg *arg)
{
	return arg->is_buffer ? arg->buffer->size : arg->size;
}

struct fuse_ops {
	uint32_t (*default_filter)(const struct bpf_fuse_meta_info *meta);

	uint32_t (*open_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in);
	uint32_t (*open_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out);

	uint32_t (*opendir_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_open_in *in);
	uint32_t (*opendir_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_open_in *in,
				struct fuse_open_out *out);

	uint32_t (*create_open_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_create_in *in, struct fuse_buffer *name);
	uint32_t (*create_open_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_create_in *in, const struct fuse_buffer *name,
				struct fuse_entry_out *entry_out, struct fuse_open_out *out);

	uint32_t (*release_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in);
	uint32_t (*release_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in);

	uint32_t (*releasedir_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_release_in *in);
	uint32_t (*releasedir_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_release_in *in);

	uint32_t (*flush_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_flush_in *in);
	uint32_t (*flush_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_flush_in *in);

	uint32_t (*lseek_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_lseek_in *in);
	uint32_t (*lseek_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_lseek_in *in,
				struct fuse_lseek_out *out);

	uint32_t (*copy_file_range_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_copy_file_range_in *in);
	uint32_t (*copy_file_range_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_copy_file_range_in *in,
				struct fuse_write_out *out);

	uint32_t (*fsync_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in);
	uint32_t (*fsync_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in);

	uint32_t (*dir_fsync_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_fsync_in *in);
	uint32_t (*dir_fsync_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fsync_in *in);

	uint32_t (*getxattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in, struct fuse_buffer *name);
	// if in->size > 0, use value. If in->size == 0, use out.
	uint32_t (*getxattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in, const struct fuse_buffer *name,
				struct fuse_buffer *value, struct fuse_getxattr_out *out);

	uint32_t (*listxattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_getxattr_in *in);
	// if in->size > 0, use value. If in->size == 0, use out.
	uint32_t (*listxattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getxattr_in *in,
				struct fuse_buffer *value, struct fuse_getxattr_out *out);

	uint32_t (*setxattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_setxattr_in *in, struct fuse_buffer *name,
					struct fuse_buffer *value);
	uint32_t (*setxattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_setxattr_in *in, const struct fuse_buffer *name,
					const struct fuse_buffer *value);

	uint32_t (*removexattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name);
	uint32_t (*removexattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name);

	/* Read and Write iter will likely undergo some sort of change/addition to handle changing
	 * the data buffer passed in/out. */
	uint32_t (*read_iter_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in);
	uint32_t (*read_iter_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_iter_out *out);

	uint32_t (*write_iter_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_write_in *in);
	uint32_t (*write_iter_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_write_in *in,
				struct fuse_write_iter_out *out);

	uint32_t (*file_fallocate_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_fallocate_in *in);
	uint32_t (*file_fallocate_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_fallocate_in *in);

	uint32_t (*lookup_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name);
	uint32_t (*lookup_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name,
				struct fuse_entry_out *out, struct fuse_buffer *entries);

	uint32_t (*mknod_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_mknod_in *in, struct fuse_buffer *name);
	uint32_t (*mknod_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_mknod_in *in, const struct fuse_buffer *name);

	uint32_t (*mkdir_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_mkdir_in *in, struct fuse_buffer *name);
	uint32_t (*mkdir_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_mkdir_in *in, const struct fuse_buffer *name);

	uint32_t (*rmdir_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name);
	uint32_t (*rmdir_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name);

	uint32_t (*rename2_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_rename2_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name);
	uint32_t (*rename2_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename2_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name);

	uint32_t (*rename_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_rename_in *in, struct fuse_buffer *old_name,
				struct fuse_buffer *new_name);
	uint32_t (*rename_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_rename_in *in, const struct fuse_buffer *old_name,
				const struct fuse_buffer *new_name);

	uint32_t (*unlink_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name);
	uint32_t (*unlink_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name);

	uint32_t (*link_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_link_in *in, struct fuse_buffer *name);
	uint32_t (*link_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_link_in *in, const struct fuse_buffer *name);

	uint32_t (*getattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_getattr_in *in);
	uint32_t (*getattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_getattr_in *in,
				struct fuse_attr_out *out);

	uint32_t (*setattr_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_setattr_in *in);
	uint32_t (*setattr_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_setattr_in *in,
				struct fuse_attr_out *out);

	uint32_t (*statfs_prefilter)(const struct bpf_fuse_meta_info *meta);
	uint32_t (*statfs_postfilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_statfs_out *out);

	//TODO: This does not allow doing anything with path
	uint32_t (*get_link_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name);
	uint32_t (*get_link_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name);

	uint32_t (*symlink_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_buffer *name, struct fuse_buffer *path);
	uint32_t (*symlink_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_buffer *name, const struct fuse_buffer *path);

	uint32_t (*readdir_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_read_in *in);
	uint32_t (*readdir_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_read_in *in,
				struct fuse_read_out *out, struct fuse_buffer *buffer);

	uint32_t (*access_prefilter)(const struct bpf_fuse_meta_info *meta,
				struct fuse_access_in *in);
	uint32_t (*access_postfilter)(const struct bpf_fuse_meta_info *meta,
				const struct fuse_access_in *in);

	char name[BPF_FUSE_NAME_MAX];
};

struct bpf_fuse_ops_attach {
	int (*fuse_register_bpf)(struct fuse_ops *f_ops);
	void (*fuse_unregister_bpf)(struct fuse_ops *f_ops);
};

int register_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops);
void unregister_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops);

#endif /* _BPF_FUSE_H */
