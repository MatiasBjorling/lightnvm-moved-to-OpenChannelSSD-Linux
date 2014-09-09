#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jhash.h>
#include <linux/slab.h>
#include "vsl.h"

/*inflight only uses jenkins hash - less to compare, collisions only result
 *  in unecessary serialisation.
 *
 *could restrict oneself to only grabbing table lock whenever you specifically
 *  want a new entry -- otherwise no concurrent threads will ever be interested
 *  in the same entry
 */

#define BUCKET_LEN 16
#define BUCKET_OCCUPANCY_AVG (BUCKET_LEN / 4)

struct kv_inflight {
	struct list_head list;
	u32	h1;
};

struct kv_entry {
	u64 hash[2];
	struct vsl_block *blk;
};

struct vslkv_io {
	int offset;
	unsigned npages;
	unsigned length;
	struct page **pages;
	struct vsl_block *block;
	int write;
};

enum KVIO {
	KVIO_READ	= 0,
	KVIO_WRITE	= 1,
};

enum LOOKUP_TYPE {
	EXISTING_ENTRY	= 0,
	NEW_ENTRY	= 1,
};

static inline unsigned bucket_idx(struct vslkv_tbl *tbl, u32 hash)
{
	return (hash % (tbl->tbl_len/BUCKET_LEN));
}

/*TODO FIXME - no locks can be held while executing this*/
static void inflight_lock(struct vslkv_inflight *ilist,
			struct kv_inflight *ientry)
{
	struct kv_inflight *lentry;
	unsigned long flags;

retry:
	spin_lock_irqsave(&ilist->lock, flags);

	list_for_each_entry(lentry, &ilist->list, list) {
		if (lentry->h1 == ientry->h1) {
			spin_unlock_irqrestore(&ilist->lock, flags);
			schedule();
			goto retry;
		}
	}

	list_add_tail(&ientry->list, &ilist->list);
	spin_unlock_irqrestore(&ilist->lock, flags);
}

static void inflight_unlock(struct vslkv_inflight *ilist, u32 h1)
{
	struct kv_inflight *lentry;
	unsigned long flags;

	spin_lock_irqsave(&ilist->lock, flags);
	BUG_ON(list_empty(&ilist->list));

	list_for_each_entry(lentry, &ilist->list, list) {
		if (lentry->h1 == h1) {
			list_del(&lentry->list);
			goto out;
		}
	}

	BUG(); //Should never be called without an entry in the list.
out:
	spin_unlock_irqrestore(&ilist->lock, flags);
}

/*TODO reserving '0' for empty entries is technically a no-go as it could be
  a hash value.*/
static int __tbl_get_idx(struct vslkv_tbl *tbl, u32 h1, u64 *h2,
			enum LOOKUP_TYPE type)
{
	unsigned b_idx = bucket_idx(tbl, h1);
	unsigned idx = BUCKET_LEN * b_idx;
	unsigned i;
	struct kv_entry *entry = &tbl->entries[idx];

	printk("__tbl_get_idx: looking in bucket %u (of %llu) (t:%s)\n",
		b_idx, tbl->tbl_len/BUCKET_LEN, (type == NEW_ENTRY ? "NEW" : "EXISTING"));
	for (i = 0; i < BUCKET_LEN; i++, entry++) {
		printk("\t__tbl_get_idx(%d/%d)\n", i, BUCKET_LEN);
		printk("\t\th2[0](%llu) - e->h2[0](%llu)\n", h2[0], entry->hash[0]);
		printk("\t\th2[1](%llu) - e->h2[1](%llu)\n", h2[1], entry->hash[1]);
		if (memcmp(entry->hash, h2, sizeof(u64)*2) == 0) {
			if (type == NEW_ENTRY)
				entry->hash[0] = 1;
			idx += i;
			break;
		}
	}

	if (i == BUCKET_LEN)
		idx = -1;

	return idx;
}

static int tbl_get_idx(struct vslkv_tbl *tbl, u32 h1, u64 *h2,
		enum LOOKUP_TYPE type)
{
	unsigned long flags;
	int idx;

	printk("tbl_get_idx start\n");

	spin_lock_irqsave(&tbl->lock, flags);
	idx = __tbl_get_idx(tbl, h1, h2, type);
	spin_unlock_irqrestore(&tbl->lock, flags);
	return idx;
}

static int tbl_new_entry(struct vslkv_tbl *tbl, u32 h1)
{
	u64 empty[2] = { 0, 0 };
	return tbl_get_idx(tbl, h1, empty, NEW_ENTRY);
}

static inline u32 hash1(void *key, unsigned length)
{
	u32 ret, blocks, tmp;
	u32 *p = (u32*)key;
	blocks = length / sizeof(u32);
	tmp = length % sizeof(u32);

	if (tmp) {
		memcpy(&tmp, p+blocks, tmp);
		ret = jhash2(p, blocks, 0);
		return jhash2(&tmp, 1, ret);
	}
	return jhash2(p, blocks, 0);
}

static inline void hash2(void *dst, void *src, size_t src_len)
{
	struct scatterlist sg;
	struct hash_desc hdesc;

	sg_init_one(&sg, src, src_len);
	hdesc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	crypto_hash_init(&hdesc);
	crypto_hash_update(&hdesc, &sg, src_len);
	crypto_hash_final(&hdesc, (u8*)dst);
	crypto_free_hash(hdesc.tfm);
}

static inline void *cpy_val(u64 addr, size_t len)
{
	void *buf = NULL;
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) {
		printk("cpy_val: -ENOMEM #1\n");
		return ERR_PTR(-ENOMEM);
	}
	if(copy_from_user(buf, (void*)addr, len)) {
		printk("cpy_val: -EFAULT #1\n");
		kfree(buf);
		return ERR_PTR(-EFAULT);
	}
	return buf;
}

static struct vslkv_io *map_user_io(u64 addr, unsigned length, enum KVIO do_write)
{
	int offset, pcount, ret, i;
	struct page **pages;
	struct vslkv_io *vkv_io = NULL;

	if (addr & 3)
		return ERR_PTR(-EINVAL);
	if (!length || length > INT_MAX - PAGE_SIZE)
		return ERR_PTR(-EINVAL); /*TODO cap @ blk erase size minus key size*/

	offset = offset_in_page(addr);
	pcount = DIV_ROUND_UP(offset + length, PAGE_SIZE);
	pages = kcalloc(pcount, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return ERR_PTR(-ENOMEM);

	ret = get_user_pages_fast(addr, pcount, do_write, pages);
	if (ret < pcount) {
		pcount = ret;
		ret = -EFAULT;
		goto put_pages;
	}

	vkv_io = kmalloc(sizeof(vkv_io), GFP_KERNEL);
	if (!vkv_io) {
		ret = -ENOMEM;
		goto put_pages;
	}

	vkv_io->offset = offset;
	vkv_io->npages = pcount;
	vkv_io->length = length;
	vkv_io->pages = pages;
	vkv_io->write = do_write;
	return vkv_io;

put_pages:
	for (i = 0; i < pcount; i++)
		put_page(pages[i]);
	kfree(pages);
	return ERR_PTR(ret);
}

static void unmap_user_io(struct vslkv_io *vkv_io)
{
	int i;
	for (i = 0; i < vkv_io->npages; i++)
		put_page(vkv_io->pages[i]);

	kfree(vkv_io->pages);
	kfree(vkv_io);
}

static int do_io(struct vsl_stor *s, int rw, u64 blk_addr, void __user *ubuf,
		unsigned long len)
{
	struct vsl_dev *dev = s->dev;
	struct request_queue *q = dev->q;
	struct rq_map_data map_data;
	struct request *rq;
	int ret;

	printk("[KV> do_io start\n");
	rq = blk_mq_alloc_request(q, rw, GFP_KERNEL, false);
	if (!rq) {
		pr_err("[KV]do_io: failed to allocate request\n");
		ret = -ENOMEM;
		goto out;
	}
	printk("[KV> do_io blk_rq_map_user(q, rq, map_data, ubuf:%llx, len:%lu, GFP_ATOMIC\n",
		(u64)ubuf, len);
	ret = blk_rq_map_user(q, rq, &map_data, ubuf, len, GFP_ATOMIC);
	if (ret) {
		pr_err("[KV]do_io: failed to map userspace memory into request (err:%d)\n", ret);
		goto err_umap;
	}

	rq->cmd_flags |= REQ_VSL_PASSTHRU;
	rq->__sector = blk_addr * NR_PHY_IN_LOG;
	rq->errors = 0;
	printk("[KV> do_io -- issuing I/O against addr:%llu(PHY:%lu)\n", blk_addr, rq->__sector);

	printk("[KV> do_io blk_execute_rq\n");
	ret = blk_execute_rq(q, dev->disk, rq, 0);
	if (ret)
		pr_err("[KV]do_io: failed to execute request..\n");
	else
		pr_info("[KV]do_io: omgeeee write worked without a hitch!\n");

	printk("[KV> do_io blk_rq_unmap_user\n");
	blk_rq_unmap_user(rq->bio);

err_umap:
	blk_put_request(rq);
out:
	return ret;
}

/**
 *	get	-	get value from KV store
 *	@s: vsl stor
 *	@cmd: VSL KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Fetch value identified by the supplied key.
 */
static int get(struct vsl_stor *s, struct vsl_cmd_kv *cmd, void *key, u32 h1)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int ret = 0;

	hash2(&h2, key, cmd->key_len);

	if ((ret = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY)) != -1) {
		printk("[KV]get: found entry\n");
		entry = &tbl->entries[ret];
	} else {
		printk("[KV]get: could not find entry!\n");
		return -1;
	}

	ret = do_io(s, READ, block_to_addr(entry->blk),
		(void __user *)cmd->val_addr, cmd->val_len);

	return ret;
}

static struct vsl_block *acquire_block(struct vsl_stor *s)
{
	int i;
	struct vsl_ap *ap = NULL;
	struct vsl_pool *pool = NULL;
	struct vsl_block *block = NULL;

	for(i = 0; i < s->nr_aps; i++) {
		ap = get_next_ap(s);
		pool = ap->pool;

		block = s->type->pool_get_blk(pool, 0);
		if (block)
			break;
	}
	return block;
}


#define err(msg) printk("ERR<%s>%d: " msg, __FUNCTION__, __LINE__)
static void __dump_mem(void *b, unsigned len)
{
	unsigned *c = (unsigned *)b;
	unsigned off, end;

	end = len / sizeof(unsigned);
	for (off = 0; off < end; off++, c++)
		printk("%x", (unsigned)*c);
	printk("\n");
}
#define dump_mem(p, len) \
	printk("\nDUMP " #len " bytes OF '" #p "'\n"); \
	__dump_mem((p), (len));

static int verify_io(struct vsl_stor *s, u64 blk_addr)
{
	struct vsl_dev *dev = s->dev;
	struct bio *b;
	struct request *rq;
	struct request_queue *q = dev->q;
	struct page *page;
	void *buf;
	int ret = 0;

	printk("verify_io begin------------------\n");
	b = bio_alloc(GFP_NOIO, 1);
	if (!b) {
		err("couldn't alloc bio\n");
		ret = -ENOMEM;
		goto err_balloc;
	}
	b->bi_iter.bi_sector = blk_addr * NR_PHY_IN_LOG;
	
	page = mempool_alloc(s->page_pool, GFP_NOIO);
	if (!page) {
		err("failed to allocate a page!!!\n");
		goto err_palloc;
	}
	buf = page_address(page);
	memset(buf, 0x00, EXPOSED_PAGE_SIZE);
	dump_mem(buf, 100);

	ret = bio_add_pc_page(q, b, page, EXPOSED_PAGE_SIZE, 0);
	if (ret == 0) {
		err("failed to add anything\n");
		goto err_addpage;
	}

	rq = blk_mq_alloc_request(q, READ, GFP_KERNEL, false);
	if (!rq) {
		mempool_free(page, s->page_pool);
		err("failed to alloc verify io request\n");
		goto err_rqalloc;
	}
	blk_init_request_from_bio(rq, b);

	ret = blk_execute_rq(q, dev->disk, rq, 0);
	if (ret) {
		err("-EIO from blk_execute_rq\n");
	}
	buf = page_address(page);
	dump_mem(buf, 100);

	blk_put_request(rq);
err_rqalloc:
	mempool_free(page, s->page_pool);
err_addpage:
err_palloc:
	bio_put(b);
err_balloc:
	return ret;
}

static int update_entry(struct vsl_stor *s, struct vsl_cmd_kv *cmd,
			struct kv_entry *entry, int existing)
{
	struct vsl_block *block;
	int ret;

	BUG_ON(!s);
	BUG_ON(!cmd);
	BUG_ON(!entry);

	block = acquire_block(s);
	if (!block) {
		printk("[KV]update_entry: failed to acquire a block\n");
		ret = -ENOSPC;
		goto no_block;
	}
	printk("[KV> found a block to write to...! (pre do_io)(id:%u,%lu)\n", block->id, block_to_addr(block));
	printk("[KV> update_entry, cmd->val_addr [u64](%llx)\n", cmd->val_addr);
	//printk("[KV>verify_io **PRE UPDATE**\n");
	//verify_io(s, block_to_addr(block));
	ret = do_io(s, WRITE, block_to_addr(block),
		(void __user *)cmd->val_addr, cmd->val_len);
	if (ret) {
		printk("[KV]update_entry: failed to write entry\n");
		ret = -EIO;
		goto io_err;
	}

	if (existing)
		s->type->pool_put_blk(entry->blk);
	entry->blk = block;

	printk("[KV>verify_io **POST UPDATE**\n");
	verify_io(s, block_to_addr(block));
	return ret;
io_err:
	s->type->pool_put_blk(block);
no_block:
	return ret;
}

/**
 *	put	-	put/update value in KV store
 *	@s: vsl stor
 *	@cmd: VSL KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Store the supplied value in an entry identified by the
 *	supplied key. Will overwrite existing entry if necessary.
 */
static int put(struct vsl_stor *s, struct vsl_cmd_kv *cmd, void *key, u32 h1)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int ret = -1;
	int existing = 0;
	printk("put start\n");

	hash2(&h2, key, cmd->key_len);
	printk("put post hash\n");

	if ((ret = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY)) != -1) {
		printk("[KV]put: overwriting entry\n");
		entry = &tbl->entries[ret];
		existing = 1;
	} else if ((ret = tbl_new_entry(tbl, h1)) != -1) {
		printk("[KV]put: inserting new entry\n");
		entry = &tbl->entries[ret];
		printk("[KV> ref entry\n");
		memcpy(entry->hash, &h2, sizeof(entry->hash));
		printk("[KV> wrote hash\n");
	} else {
		printk("[KV]put: FATAL no matching entry, no empty entries!!\n");
		BUG();
	}

	printk("[KV> b4 update_entry\n");
	if ((ret = update_entry(s, cmd, entry, existing)) && !existing) {
		memset(entry->hash, 0, sizeof(entry->hash));
	}
	return ret;
}

/**
 *	update	-	 update existing entry
 *	@s: vsl stor
 *	@cmd: VSL KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Updates existing value identified by 'k' to the new value.
 *	Operation only succeeds if k points to an existing value.
 */
static int update(struct vsl_stor *s, struct vsl_cmd_kv *cmd, void *key, u32 h1)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int ret = -1;

	hash2(&h2, key, cmd->key_len);

	if ((ret = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY)) != -1) {
		printk("[KV]put: overwriting entry\n");
		entry = &tbl->entries[ret];
	} else {
		printk("[KV]update: no entry - skipping\n");
		return 0;
	}

	if ((ret = update_entry(s, cmd, entry, 0))) {
		memset(entry->hash, 0, sizeof(entry->hash));
	}
	return ret;
}

/**
 *	del	 -	 delete entry.
 *	@s: vsl stor
 *	@cmd: VSL KV command
 *	@key: copy of key supplied from userspace.
 *	@h1: hash of key value using hash function 1
 *
 *	Removes the value associated the supplied key.
 */
static int del(struct vsl_stor *s, struct vsl_cmd_kv *cmd, void *key, u32 h1)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct kv_entry *entry;
	u64 h2[2];
	int idx = 0;

	hash2(&h2, key, cmd->key_len);

	if ((idx = tbl_get_idx(tbl, h1, h2, EXISTING_ENTRY)) != -1) {
		printk("[KV]del: deleting entry\n");
		entry = &tbl->entries[idx];
		s->type->pool_put_blk(entry->blk);
		memset(entry, 0, sizeof(struct kv_entry));
	} else {
		printk("[KV]del: could not find entry!\n");
	}

	return 0;
}

int vslkv_unpack(struct vsl_dev *dev, struct vsl_cmd_kv __user *ucmd)
{
	struct vsl_cmd_kv cmd;
	struct vsl_stor *s = dev->stor;
	struct vslkv_inflight *inflight = &s->kv.inflight;

	struct kv_inflight *ientry;
	u32 h1;
	void *key;
	int ret = 0;

	if(copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;

	key = cpy_val(cmd.key_addr, cmd.key_len);
	if (IS_ERR(key)) {
		ret = -ENOMEM;
		goto out;
	}

	h1 = hash1(key, cmd.key_len);
	ientry = kmem_cache_alloc(inflight->entry_pool, GFP_KERNEL);
	if (!ientry) {
		ret = -ENOMEM;
		goto err_ientry;
	}
	ientry->h1 = h1;
	inflight_lock(inflight, ientry);

	switch(cmd.opcode) {
	case VSL_KV_GET:
		ret = get(s, &cmd, key, h1);
		break;
	case VSL_KV_PUT:
		ret = put(s, &cmd, key, h1);
		break;
	case VSL_KV_UPDATE:
		ret = update(s, &cmd, key, h1);
		break;
	case VSL_KV_DEL:
		ret = del(s, &cmd, key, h1);
		break;
	default:
		ret = -1;
		break;
	}

	inflight_unlock(inflight, h1);

err_ientry:
	kfree(key);
out:
	return ret;
}

static inline unsigned long num_entries(struct vsl_stor *s, unsigned long size)
{
	return size / s->gran_blk;
}

int vslkv_init(struct vsl_stor *s, unsigned long size)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct vslkv_inflight *inflight = &s->kv.inflight;
	int ret = 0;

	unsigned long buckets = num_entries(s, size)
		/ (BUCKET_LEN / BUCKET_OCCUPANCY_AVG);

	tbl->bucket_len = BUCKET_LEN;
	tbl->tbl_len = buckets * tbl->bucket_len;

	tbl->entries = vzalloc(
		tbl->tbl_len * sizeof(struct kv_entry));
	if (!tbl->entries) {
		printk("vslkv_init: failed to allocate KV table :'(\n");
		ret = -ENOMEM;
		goto err_tbl_entries;
	}

	inflight->entry_pool = kmem_cache_create("vslkv_inflight_pool",
			sizeof(struct kv_inflight), 0,
			SLAB_RECLAIM_ACCOUNT | SLAB_MEM_SPREAD,
			NULL);
	if (!inflight->entry_pool) {
		ret = -ENOMEM;
		goto err_inflight_pool;
	}

	spin_lock_init(&tbl->lock);
	INIT_LIST_HEAD(&inflight->list);
	spin_lock_init(&inflight->lock);

	return 0;

err_inflight_pool:
	vfree(tbl->entries);
err_tbl_entries:
	return ret;
}

void vslkv_exit(struct vsl_stor *s)
{
	struct vslkv_tbl *tbl = &s->kv.tbl;
	struct vslkv_inflight *inflight = &s->kv.inflight;

	vfree(tbl->entries);
	kmem_cache_destroy(inflight->entry_pool);
}
