// SPDX-License-Identifier: GPL-2.0
/*
 * FUSE-BPF: Filesystem in Userspace with BPF
 * Copyright (c) 2021 Google LLC
 */

#include <linux/bpf_verifier.h>
#include <linux/bpf_fuse.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/hashtable.h>

#include "fuse_i.h"

struct fuse_ops tmp_f_op_empty = { 0 };
struct fuse_ops *tmp_f_op = &tmp_f_op_empty;

struct hashtable_entry {
	struct hlist_node hlist;
	struct hlist_node dlist; /* for deletion cleanup */
	struct qstr key;
	struct fuse_ops *ops;
};

static DEFINE_HASHTABLE(name_to_ops, 8);

static unsigned int full_name_case_hash(const void *salt, const unsigned char *name, unsigned int len)
{
	unsigned long hash = init_name_hash(salt);

	while (len--)
		hash = partial_name_hash(tolower(*name++), hash);
	return end_name_hash(hash);
}

static inline void qstr_init(struct qstr *q, const char *name)
{
	q->name = name;
	q->len = strlen(q->name);
	q->hash = full_name_case_hash(0, q->name, q->len);
}

static inline int qstr_copy(const struct qstr *src, struct qstr *dest)
{
	dest->name = kstrdup(src->name, GFP_KERNEL);
	dest->hash_len = src->hash_len;
	return !!dest->name;
}

static inline int qstr_eq(const struct qstr *s1, const struct qstr *s2)
{
	int res, r1, r2, r3;

	r1 = s1->len == s2->len;
	r2 = s1->hash == s2->hash;
	r3 = memcmp(s1->name, s2->name, s1->len);
	res = (s1->len == s2->len && s1->hash == s2->hash && !memcmp(s1->name, s2->name, s1->len));
	return res;
}

static struct fuse_ops *__find_fuse_ops(const struct qstr *key)
{
	struct hashtable_entry *hash_cur;
	unsigned int hash = key->hash;
	struct fuse_ops *ret_ops;

	rcu_read_lock();
	hash_for_each_possible_rcu(name_to_ops, hash_cur, hlist, hash) {
		if (qstr_eq(key, &hash_cur->key)) {
			ret_ops = hash_cur->ops;
			ret_ops = get_fuse_ops(ret_ops);
			rcu_read_unlock();
			return ret_ops;
		}
	}
	rcu_read_unlock();
	return NULL;
}

struct fuse_ops *get_fuse_ops(struct fuse_ops *ops)
{
	if (bpf_try_module_get(ops, BPF_MODULE_OWNER))
		return ops;
	else
		return NULL;
}

void put_fuse_ops(struct fuse_ops *ops)
{
	if (ops)
		bpf_module_put(ops, BPF_MODULE_OWNER);
}

struct fuse_ops *find_fuse_ops(const char *key)
{
	struct qstr q;

	qstr_init(&q, key);
	return __find_fuse_ops(&q);
}

static struct hashtable_entry *alloc_hashtable_entry(const struct qstr *key,
		struct fuse_ops *value)
{
	struct hashtable_entry *ret = kzalloc(sizeof(*ret), GFP_KERNEL);
	if (!ret)
		return NULL;
	INIT_HLIST_NODE(&ret->dlist);
	INIT_HLIST_NODE(&ret->hlist);

	if (!qstr_copy(key, &ret->key)) {
		kfree(ret);
		return NULL;
	}

	ret->ops = value;
	return ret;
}

static int __register_fuse_op(struct fuse_ops *value)
{
	struct hashtable_entry *hash_cur;
	struct hashtable_entry *new_entry;
	struct qstr key;
	unsigned int hash;

	qstr_init(&key, value->name);
	hash = key.hash;
	hash_for_each_possible_rcu(name_to_ops, hash_cur, hlist, hash) {
		if (qstr_eq(&key, &hash_cur->key)) {
			return -EEXIST;
		}
	}
	new_entry = alloc_hashtable_entry(&key, value);
	if (!new_entry)
		return -ENOMEM;
	hash_add_rcu(name_to_ops, &new_entry->hlist, hash);
	return 0;
}

static int register_fuse_op(struct fuse_ops *value)
{
	int err;

	if (bpf_try_module_get(value, BPF_MODULE_OWNER))
		err = __register_fuse_op(value);
	else
		return -EBUSY;

	return err;
}

static void unregister_fuse_op(struct fuse_ops *value)
{
	struct hashtable_entry *hash_cur;
	struct qstr key;
	unsigned int hash;
	struct hlist_node *h_t;
	HLIST_HEAD(free_list);

	qstr_init(&key, value->name);
	hash = key.hash;

	hash_for_each_possible_rcu(name_to_ops, hash_cur, hlist, hash) {
		if (qstr_eq(&key, &hash_cur->key)) {
			hash_del_rcu(&hash_cur->hlist);
			hlist_add_head(&hash_cur->dlist, &free_list);
		}
	}
	synchronize_rcu();
	bpf_module_put(value, BPF_MODULE_OWNER);
	hlist_for_each_entry_safe(hash_cur, h_t, &free_list, dlist)
		kfree(hash_cur);
}

static void fuse_op_list_destroy(void)
{
	struct hashtable_entry *hash_cur;
	struct hlist_node *h_t;
	HLIST_HEAD(free_list);
	int i;

	//mutex_lock(&sdcardfs_super_list_lock);
	hash_for_each_rcu(name_to_ops, i, hash_cur, hlist) {
		hash_del_rcu(&hash_cur->hlist);
		hlist_add_head(&hash_cur->dlist, &free_list);
	}
	synchronize_rcu();
	hlist_for_each_entry_safe(hash_cur, h_t, &free_list, dlist)
		kfree(hash_cur);
	//mutex_unlock(&sdcardfs_super_list_lock);
	pr_info("fuse: destroyed fuse_op list\n");
}

static struct bpf_fuse_ops_attach bpf_fuse_ops_connect = {
	.fuse_register_bpf = &register_fuse_op,
	.fuse_unregister_bpf = &unregister_fuse_op,
};

int init_fuse_bpf(void)
{
	return register_fuse_bpf(&bpf_fuse_ops_connect);
}

void uninit_fuse_bpf(void)
{
	unregister_fuse_bpf(&bpf_fuse_ops_connect);
	fuse_op_list_destroy();
}
