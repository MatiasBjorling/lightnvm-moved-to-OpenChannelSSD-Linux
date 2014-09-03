#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/jhash.h>
#include "vsl.h"

#define BUCKET_LEN 16
#define BUCKET_OCCUPANCY_AVG (BUCKET_LEN / 4)

struct vslkv_io {
	int offset;
	unsigned npages;
	unsigned length;
	struct page **pages;
	int write;
};

enum KVIO {
	KVIO_READ	= 0,
	KVIO_WRITE	= 1,
};

static inline unsigned bucket_idx(struct vsl_stor *s, u32 hash)
{
	return (hash % s->kv_tbl.tbl_len);
}

static inline u32 h1(void *key, unsigned length)
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

static inline void h2(void *dst, void *src, size_t src_len)
{
	struct scatterlist sg;
	struct hash_desc hdesc;

	sg_init_one(&sg, src, src_len);
	hdesc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	/*cfg hash eng. to supplied hash desc*/
	crypto_hash_init(&hdesc);

	/*performs actual hash*/
	crypto_hash_update(&hdesc, &sg, src_len);

	/*copy hash to result arr*/
	crypto_hash_final(&hdesc, (u8*)dst);

	/*clean*/
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

typedef u64 vslkey_t;

/**
 *	vslkv_get	-	get value from KV store
 *	@k: key identifying the requested value.
 */
static void *vslkv_get(vslkey_t k)
{
	return NULL;
}

/**
 *	asd
 *	vslkv_put	-	put value into KV store
 *	@k: key to reference value by
 *	@v: value to store
 *
 *	Store the supplied value in an entry identified by the
 *	supplied key. Will overwrite existing entry if necessary.
 */
static int vslkv_put(struct vsl_cmd_kv *cmd, void *key)
{
	struct vslkv_io *vkv_io;
	int ret = 0;

	printk("vslkv_put: key{%s}=>jhash2(%u)\n", (char*)key,
		h1(key, cmd->key_len));

	vkv_io = map_user_io(cmd->val_addr, cmd->val_len, KVIO_READ);
	if (IS_ERR(vkv_io)) {
		printk("vslkv_put mapping failed\n");
		ret = PTR_ERR(vkv_io);
		goto out;
	} else {
		printk("vslkv_put: mapping succeeded\n");
	}
	unmap_user_io(vkv_io);
out:
	return ret;
}


/**
 *	vslkv_update	-	 update entry
 *	@k: key to reference value by
 *	@v: updated value
 *
 *	Updates existing value identified by 'k' to the new value.
 *	Operation only succeeds if k points to an existing value.
 */
static int vslkv_update(vslkey_t k, void *v)
{
	return 0;
}

/**
 *	vslkv_del	 -	 delete entry.
 *	@k: key referencing value to delete
 *
 *	Removes the value associated the supplied key.
 */
static int vslkv_del(vslkey_t k)
{
	return 0;
}

int vslkv_unpack(struct vsl_dev *dev, struct vsl_cmd_kv __user *ucmd)
{
	struct vsl_cmd_kv cmd;
	void *key;
	int ret = 0;
	printk("vslkv_unpack: VSL KV --- unpacking args\n");

	if(copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;

	printk("copying key '%llx', len: %u\n", cmd.key_addr, (u32)cmd.key_len);
	key = cpy_val(cmd.key_addr, cmd.key_len);
	if (IS_ERR(key)) {
		printk("failed to cpy cmd key\n");
		ret = PTR_ERR(key);
		goto out;
	}

	switch(cmd.opcode) {
	case VSL_KV_GET:
		printk("vslkv_unpack: GET\n");
		break;
	case VSL_KV_PUT:
		printk("vslkv_unpack: PUT\n");
		ret = vslkv_put(&cmd, key);
		break;
	case VSL_KV_UPDATE:
		printk("vslkv_unpack: UPDATE\n");
		break;
	case VSL_KV_DEL:
		printk("vslkv_unpack: DEL\n");
		break;
	default:
		printk("vslkv_unpack: opcode unrecognized :/\n");
		return -1;
	}

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
	unsigned long buckets = num_entries(s, size)
		/ (BUCKET_LEN / BUCKET_OCCUPANCY_AVG);

	s->kv_tbl.tbl_len = buckets * BUCKET_LEN;

	s->kv_tbl.entries = vzalloc(
		s->kv_tbl.tbl_len * sizeof(struct vslkv_entry));
	if (!s->kv_tbl.entries) {
		printk("vslkv_init: failed to allocate KV table :'(\n");
		return -ENOMEM;
	}
	return 0;
}

void vslkv_exit(struct vsl_stor *s)
{
	vfree(s->kv_tbl.entries);
}
