// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2021 Google LLC

#include <linux/filter.h>
#include <linux/bpf.h>
#include <linux/bpf_fuse.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>

void *bpf_fuse_get_writeable(struct fuse_buffer *arg, u64 size, bool copy)
{
	void *writeable_val;

	if (arg->flags & BPF_FUSE_IMMUTABLE)
		return 0;

	if (size <= arg->size &&
			(!(arg->flags & BPF_FUSE_MUST_ALLOCATE) ||
			  (arg->flags & BPF_FUSE_ALLOCATED))) {
		if (arg->flags & BPF_FUSE_VARIABLE_SIZE)
			arg->size = size;
		arg->flags |= BPF_FUSE_MODIFIED;
		return arg->data;
	}
	/* Variable sized arrays must stay below max size. If the buffer must be fixed size,
	 * don't change the allocated size. Verifier will enforce requested size for accesses
	 */
	if (arg->flags & BPF_FUSE_VARIABLE_SIZE) {
		if (size > arg->max_size)
			return 0;
	} else {
		if (size > arg->size)
			return 0;
		size = arg->size;
	}

	if (size != arg->size && size > arg->max_size)
		return 0;

	/* If our buffer is big enough, just adjust size */
	if (size <= arg->alloc_size) {
		if (!copy)
			arg->size = size;
		arg->flags |= BPF_FUSE_MODIFIED;
		return arg->data;
	}

	writeable_val = kzalloc(size, GFP_KERNEL);
	if (!writeable_val)
		return 0;

	arg->alloc_size = size;
	/* If we're copying the buffer, assume the same amount is used. If that isn't the case,
	 * caller must change size. Otherwise, assume entirety of new buffer is used.
	 */
	if (copy)
		memcpy(writeable_val, arg->data, (arg->size > size) ? size : arg->size);
	else
		arg->size = size;

	if (arg->flags & BPF_FUSE_ALLOCATED)
		kfree(arg->data);
	arg->data = writeable_val;

	arg->flags |= BPF_FUSE_ALLOCATED | BPF_FUSE_MODIFIED;

	return arg->data;
}
EXPORT_SYMBOL(bpf_fuse_get_writeable);

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
                  "Global kfuncs as their definitions will be in BTF");
void bpf_fuse_get_rw_dynptr(struct fuse_buffer *buffer, struct bpf_dynptr_kern *dynptr__uninit, u64 size, bool copy)
{
	buffer->data = bpf_fuse_get_writeable(buffer, size, copy);
	bpf_dynptr_init(dynptr__uninit, buffer->data, BPF_DYNPTR_TYPE_LOCAL, 0, buffer->size);
}

void bpf_fuse_get_ro_dynptr(const struct fuse_buffer *buffer, struct bpf_dynptr_kern *dynptr__uninit)
{
	bpf_dynptr_init(dynptr__uninit, buffer->data, BPF_DYNPTR_TYPE_LOCAL, 0, buffer->size);
	bpf_dynptr_set_rdonly(dynptr__uninit);
}

uint32_t bpf_fuse_return_len(struct fuse_buffer *buffer)
{
	return buffer->size;
}
__diag_pop();
BTF_SET8_START(fuse_kfunc_set)
BTF_ID_FLAGS(func, bpf_fuse_get_rw_dynptr)
BTF_ID_FLAGS(func, bpf_fuse_get_ro_dynptr)
BTF_ID_FLAGS(func, bpf_fuse_return_len)
BTF_SET8_END(fuse_kfunc_set)

static const struct btf_kfunc_id_set bpf_fuse_kfunc_set = {
	.owner = THIS_MODULE,
	.set = &fuse_kfunc_set,
};

static int __init bpf_fuse_kfuncs_init(void)
{
	return register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					 &bpf_fuse_kfunc_set);
}

late_initcall(bpf_fuse_kfuncs_init);

static const struct bpf_func_proto *bpf_fuse_get_func_proto(enum bpf_func_id func_id,
							      const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id);
	}
}

static bool bpf_fuse_is_valid_access(int off, int size,
				    enum bpf_access_type type,
				    const struct bpf_prog *prog,
				    struct bpf_insn_access_aux *info)
{
	return bpf_tracing_btf_ctx_access(off, size, type, prog, info);
}

const struct btf_type *fuse_buffer_struct_type;

static int bpf_fuse_btf_struct_access(struct bpf_verifier_log *log,
					const struct bpf_reg_state *reg,
					int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == fuse_buffer_struct_type) {
		bpf_log(log,
			"direct access to fuse_buffer is disallowed\n");
		return -EACCES;
	}

	return 0;
}

static const struct bpf_verifier_ops bpf_fuse_verifier_ops = {
	.get_func_proto		= bpf_fuse_get_func_proto,
	.is_valid_access	= bpf_fuse_is_valid_access,
	.btf_struct_access	= bpf_fuse_btf_struct_access,
};

static int bpf_fuse_check_member(const struct btf_type *t,
				   const struct btf_member *member,
				   const struct bpf_prog *prog)
{
	//if (is_unsupported(__btf_member_bit_offset(t, member) / 8))
	//	return -ENOTSUPP;
	return 0;
}

static int bpf_fuse_init_member(const struct btf_type *t,
				  const struct btf_member *member,
				  void *kdata, const void *udata)
{
	const struct fuse_ops *uf_ops;
	struct fuse_ops *f_ops;
	u32 moff;

	uf_ops = (const struct fuse_ops *)udata;
	f_ops = (struct fuse_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct fuse_ops, name):
		if (bpf_obj_name_cpy(f_ops->name, uf_ops->name,
				     sizeof(f_ops->name)) <= 0)
			return -EINVAL;
		//if (tcp_ca_find(utcp_ca->name))
		//	return -EEXIST;
		return 1;
	}

	return 0;
}

static int bpf_fuse_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "fuse_buffer", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	fuse_buffer_struct_type = btf_type_by_id(btf, type_id);

	return 0;
}

static struct bpf_fuse_ops_attach *fuse_reg = NULL;

static int bpf_fuse_reg(void *kdata)
{
	if (fuse_reg)
		return fuse_reg->fuse_register_bpf(kdata);
	pr_warn("Cannot register fuse_ops, FUSE not found");
	return -EOPNOTSUPP;
}

static void bpf_fuse_unreg(void *kdata)
{
	if(fuse_reg)
		return fuse_reg->fuse_unregister_bpf(kdata);
}

int register_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops)
{
	fuse_reg = reg_ops;
	return 0;
}
EXPORT_SYMBOL_GPL(register_fuse_bpf);

void unregister_fuse_bpf(struct bpf_fuse_ops_attach *reg_ops)
{
	if (reg_ops == fuse_reg)
		fuse_reg = NULL;
	else
		pr_warn("Refusing to unregister unregistered FUSE");
}
EXPORT_SYMBOL_GPL(unregister_fuse_bpf);

/* "extern" is to avoid sparse warning.  It is only used in bpf_struct_ops.c. */
extern struct bpf_struct_ops bpf_fuse_ops;

struct bpf_struct_ops bpf_fuse_ops = {
	.verifier_ops = &bpf_fuse_verifier_ops,
	.reg = bpf_fuse_reg,
	.unreg = bpf_fuse_unreg,
	.check_member = bpf_fuse_check_member,
	.init_member = bpf_fuse_init_member,
	.init = bpf_fuse_init,
	.name = "fuse_ops",
};

