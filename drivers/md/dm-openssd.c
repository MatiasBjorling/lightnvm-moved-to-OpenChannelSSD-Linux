/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 *
 * Todo
 *
 * - Implement translation mapping from logical to physical flash pages
 * - Implement garbage collection
 * - Implement fetching of bad pages from flash
 * 
 * Hints
 * - configurable sector size
 * - handle case of in-page bv_offset (currently hidden assumption of offset=0, and bv_len spans entire page)
 */

#include "dm-openssd.h"
#include "dm-openssd-pool.h"
#include "dm-openssd-hint.h"

#include <linux/device-mapper.h>
#include <linux/dm-io.h>
#include <linux/dm-kcopyd.h>
#include <linux/blkdev.h>
#include <linux/list.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>

/* Note: I assume hardcoded 4096 sector size. seems reasonable, but in the future we'd like this to be configurable on init */
#define SECTOR_SIZE (4096) 
#define DM_MSG_PREFIX "openssd hint mapper"
#define APS_PER_POOL 1 /* Number of append points per pool. We assume that accesses within 
						  a pool is serial (NAND flash / PCM / etc.) */

/*
	 * For now we hardcode the configuration for the OpenSSD unit that we own. In
	 * the future this should be made configurable.
	 *
	 * Configuration:
	 *
	 * Physical address space is divided into 8 chips. I.e. we create 8 pools for the
	 * addressing. We also omit the first block of each chip as they contain
	 * either the drive firmware or recordings of bad blocks.
	 *
	 */
#define POOL_COUNT 8
#define POOL_BLOCK_COUNT 128

struct openssd_dev_conf {
	unsigned short int flash_block_size; /* the number of flash pages per block */
	unsigned short int flash_page_size;  /* the flash page size in bytes */
	unsigned int num_blocks;	   /* the number of blocks addressable by the mapped SSD. */
};

struct openssd_map {
	long logical;
	long physical;
};

/* Pool descriptions */
struct openssd_pool_block {
	struct openssd_pool *parent;

	unsigned int block_id;

	unsigned next_page; /* points to the next writable page within the block */

	struct list_head list;
};

struct openssd_pool {
	/* Pool block lists */
	struct {
		spinlock_t lock;
		struct list_head used_list;
		struct list_head free_list;
	} ____cacheline_aligned_in_smp;
	unsigned long phy_addr_start;	/* References the physical start block */
	unsigned int phy_addr_end;		/* References the physical end block */

	unsigned int nr_blocks;			/* Derived value from end_block - start_block. */

	struct openssd_pool_block *blocks;
};


/*
 * openssd_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full, it requests
 * a new block, of which it continues its writes.
 */
struct openssd_ap {
	struct openssd_pool *pool;
	struct openssd_pool_block *cur;
};


/* Main structure */
struct openssd {
	struct dm_dev *dev;
	struct dm_target *ti;

	// Simple translation map of logical addresses to physical addresses. The 
	// logical addresses is known by the host system, while the physical
	// addresses are used when writing to the disk block device.
	struct openssd_map *trans_map;

	struct openssd_dev_conf dev_conf;

	/* Usually instantiated to the number of available parallel channels
	 * within the hardware device. i.e. a controller with 4 flash channels,
	 * would have 4 pools.
	 *
	 * We assume that the device exposes its channels as a linear address
	 * space. A pool therefore have a phy_addr_start and phy_addr_end that
	 * denotes the start and end. This abstraction is used to let the openssd
	 * (or any other device) expose its read/write/erase interface and be 
	 * administrated by the host system.
	 */
	struct openssd_pool *pools;

	/* Append points */
	struct openssd_ap *aps;

	int nr_pools;
	int nr_aps;
	int nr_aps_per_pool;
};

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append poing, we store it within the used_list.
 * We then move itback when its free to be used by another append point.
 *
 * The newly acclaimed block is always added to the back of user_list. As we assume
 * that the start of used list is the oldest block, and therefore higher probability
 * of invalidated pages.
 */
static struct openssd_pool_block *openssd_pool_get_block(struct openssd_pool *pool)
{
	struct openssd_pool_block *block;

	spin_lock(&pool->lock);
	if (!list_empty(&pool->free_list))
		return NULL;

	block = list_first_entry(&pool->free_list, struct openssd_pool_block, list);
	list_move_tail(&block->list, &pool->used_list);

	spin_unlock(&pool->lock);
	return block;
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby provide
 * simple (naive) wear-leveling.
 */
static void openssd_pool_put_block(struct openssd_pool_block *block)
{
	struct openssd_pool *pool = block->parent;

	spin_lock(&pool->lock);
	list_move_tail(&block->list, &pool->free_list);
	spin_unlock(&pool->lock);
}

static int openssd_pool_init(struct openssd *os, struct dm_target *ti)
{
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	int i, j;

	os->nr_aps_per_pool = APS_PER_POOL;

	os->nr_pools = POOL_COUNT;
	os->pools = kzalloc(sizeof(struct openssd_pool) * os->nr_pools, GFP_KERNEL);
	if (!os->pools)
		goto err_pool;

	ssd_for_each_pool(os, pool, i) {
		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);

		pool->phy_addr_start = i * POOL_BLOCK_COUNT;
		pool->phy_addr_end = (i + 1) * POOL_BLOCK_COUNT - 1;

		pool->nr_blocks = pool->phy_addr_end - pool->phy_addr_start + 1;
		pool->blocks = kzalloc(sizeof(struct openssd_pool_block) * pool->nr_blocks, GFP_KERNEL);
		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			block->parent = pool;
			block->block_id = pool->phy_addr_start + j;
			list_add(&(block->list), &pool->free_list);
		}
	}

	os->nr_aps = os->nr_aps_per_pool * os->nr_pools;;
	os->aps = kmalloc(sizeof(struct openssd_ap) * os->nr_pools * os->nr_aps, GFP_KERNEL);
	if (!os->aps)
		goto err_blocks;

	ssd_for_each_pool(os, pool, i) {
		for (j = 0; j < os->nr_aps_per_pool; j++) {
			ap = &os->aps[(i * os->nr_aps_per_pool) + j];

			ap->pool = pool;
			ap->cur = openssd_pool_get_block(pool);
		}
	}

	return 0;

err_blocks:
	ssd_for_each_pool(os, pool, i) {
		if (!pool->blocks)
			break;
		kfree(pool->blocks);
	}
	kfree(os->pools);
err_pool:
	ti->error = "dm-openssd: Cannot allocate openssd data structures";
	return -ENOMEM;
}

fclass file_classify(struct bio_vec* bvec) {
	fclass fc = FC_UNKNOWN;
	char *sec_in_mem;
	char byte[4];

	if(!bvec || !bvec->bv_page){
		DMINFO("can't kmap empty bvec->bv_page. kmap failed");
		return fc;
	}

	byte[0] = 0x66;
	byte[1] = 0x74;
	byte[2] = 0x79;
	byte[3] = 0x70;

	sec_in_mem = kmap_atomic((bvec->bv_page) + bvec->bv_offset);

	if(!sec_in_mem) {
		DMERR("bvec->bv_page kmap failed");
		return fc;
	}
	if(!memcmp(sec_in_mem+4, byte,4)) {
		//hint_log("VIDEO classified");
		DMINFO("VIDEO classified");
		fc = FC_VIDEO_SLOW;
	}

	kunmap_atomic(sec_in_mem);
	return fc;
}

static int openssd_send_hint(struct dm_target *ti, hint_data_t *hint_data)
{
	// TODO: call special ioctl on target?
	// for now just print and free
	DMINFO("send nothing free hint_data and simply return");
	kfree(hint_data);    

	return 0;
}

/**
 * automatically extract hint from a bio, and send to target.
 * iterate all pages, look into inode. There are several cases:
 * 1) swap - stop and send hint on entire bio (assuming swap LBAs are not mixed with regular LBAs in one bio)
 * 2) read - iterate all pages and send hint_data composed of multiple hints, one for each inode number and
 *           relevant range of LBAs covered by a page
 * 3) write - check if a page is the first sector of a file, classify it and set in hint. rest same as read
 */
static void openssd_bio_hints(struct dm_target *ti, struct bio *bio)
{
	hint_data_t *hint_data = NULL;
	uint32_t lba = 0, bio_len = 0, hint_idx;
	uint32_t sectors_count = 0;
	struct page *bv_page = NULL;
	struct address_space *mapping;
	struct inode *host;
	unsigned long prev_ino = -1, first_sector = -1;
	unsigned ino = -1;
	struct bio_vec *bvec;
	fclass fc = FC_EMPTY;
	int i, ret;
	bool is_write = 0;

    /* can classify only writes*/
	switch(bio_rw(bio)) {
		case READ:
		case READA:
			/* read/readahead*/
			break;
		case WRITE:
			is_write = 1;
			break;
		default:
			/* ? */
			return;
	}

	// get lba and sector count
	lba = bio->bi_sector;
	sectors_count = bio->bi_size / SECTOR_SIZE;

	/* allocate hint_data */
	hint_data = kmalloc(sizeof(hint_data_t), GFP_ATOMIC);
	if (hint_data == NULL) {
		DMERR("hint_data_t kmalloc failed");  
		return;
	}

	memset(hint_data, 0, sizeof(hint_data_t));
	CAST_TO_PAYLOAD(hint_data)->lba = lba;
	CAST_TO_PAYLOAD(hint_data)->sectors_count = sectors_count;
	CAST_TO_PAYLOAD(hint_data)->is_write = is_write;
	ino = -1;            
	DMINFO("%s lba=%d sectors_count=%d", is_write?"WRITE":"READ", lba, sectors_count);
#if 0
	hint_log("free hint_data dont look in bvec. simply return");
	kfree(hint_data);
	return;
#endif

	bio_for_each_segment(bvec, bio, i) {
		bv_page = bvec[0].bv_page;

		if (bv_page && !PageSlab(bv_page)) {
			// swap hint
			if(PageSwapCache(bv_page)) {
				DMINFO("swap bio");
				// TODO - not tested
				CAST_TO_PAYLOAD(hint_data)->is_swap = 1;

				// for compatibility add one hint
				INO_HINT_SET(hint_data, CAST_TO_PAYLOAD(hint_data)->count,
								0, lba, sectors_count, fc);
				CAST_TO_PAYLOAD(hint_data)->count++;
              break;
		}

			mapping = bv_page->mapping;
//				continue;
		if (mapping && ((unsigned long)mapping & PAGE_MAPPING_ANON) == 0) {
			host = mapping->host;
			if (!host) {
				DMCRIT("page without mapping->host. shouldn't happen\n");
				bio_len+= bvec[0].bv_len;
				continue; // no host
			}

			prev_ino = ino;
			ino = host->i_ino;

			if(!host->i_sb || !host->i_sb->s_type || !host->i_sb->s_type->name){
				DMINFO("not related to file system");
				bio_len+= bvec[0].bv_len;
				continue;
			}

			if(!ino) {
				DMINFO("not inode related");
				bio_len+= bvec[0].bv_len;
				continue;
			}
			//if(bvec[0].bv_offset) 
			//   DMINFO("bv_page->index %d offset %d len %d", bv_page->index, bvec[0].bv_offset, bvec[0].bv_len);

			/* classify if we can.
			 * can only classify writes to file's first sector */
			fc = FC_EMPTY;
			if (is_write && bv_page->index == 0 && bvec[0].bv_offset ==0) {
				// should be first sector in file. classify
				first_sector = lba + (bio_len / SECTOR_SIZE);
				fc = file_classify(&bvec[0]); 
			}

			/* change previous hint, unless this is a new inode
			   and then simply increment count in existing hint */
			if(prev_ino == ino) {
				hint_idx = CAST_TO_PAYLOAD(hint_data)->count-1;
				if(INO_HINT_FROM_DATA(hint_data, hint_idx).ino != ino) {
					DMERR("updating hint of wrong ino (ino=%u expected=%lu)", ino,
						INO_HINT_FROM_DATA(hint_data, hint_idx).ino);            
					bio_len+= bvec[0].bv_len;
					continue;
				}

					INO_HINT_FROM_DATA(hint_data, hint_idx).count += bvec[0].bv_len / SECTOR_SIZE;
					DMINFO("increase count for hint %u. new count=%u", 
					hint_idx, INO_HINT_FROM_DATA(hint_data, hint_idx).count);
					bio_len+= bvec[0].bv_len;
					continue;
				}

				if(HINT_DATA_MAX_INOS == CAST_TO_PAYLOAD(hint_data)->count){
					DMERR("too many inos in hint");
					bio_len+= bvec[0].bv_len;
					continue;
				}

				DMINFO("add %s hint here - ino=%u lba=%u fc=%s count=%d hint_count=%u", 
					is_write?"WRITE":"READ", ino, lba + (bio_len / SECTOR_SIZE), 
					 (fc==FC_VIDEO_SLOW)?"VIDEO":(fc==FC_EMPTY)?"EMPTY":"UNKNOWN", 
					 bvec[0].bv_len / SECTOR_SIZE, CAST_TO_PAYLOAD(hint_data)->count+1);

				// add new hint to hint_data. lba count=bvec[0].bv_len / SECTOR_SIZE, will add more later on
				INO_HINT_SET(hint_data, CAST_TO_PAYLOAD(hint_data)->count, 
					ino, lba + (bio_len / SECTOR_SIZE), bvec[0].bv_len / SECTOR_SIZE, fc);
				CAST_TO_PAYLOAD(hint_data)->count++;
			}
		}

		// increment len
		bio_len+= bvec[0].bv_len;
	}
#if 0
	// TESTING
	// dont send hints yet. just print whatever we got, and free
	hint_log("send nothing free hint_data and simply return.");
	kfree(hint_data);
	hint_log("return");
	return;
#endif
	// hint empty - return.
	// Note: not error, maybe we're not doing file-related/swap I/O
	if(CAST_TO_PAYLOAD(hint_data)->count==0){
		//hint_log("request with no file data");
		kfree(hint_data);
		return;
	}

	/* non-empty hint_data, send to device */
	//hint_log("hint count=%u. send to hint device", CAST_TO_PAYLOAD(hint_data)->count);
	ret = openssd_send_hint(ti, hint_data);

	if (ret != 0) {
		DMINFO("openssd_send_hint error %d", ret);
		return;
	}
}

/*----------------------------------------------------------------
 * OpenSSD target methods
 *
 * ctr - Constructor
 * dtr - Destructor
 * map - Maps and execute a given IO.
 *--------------------------------------------------------------*/

/*
 * Accepts an OpenSSD-backed block-device. The OpenSSD device should run the
 * corresponding physical firmware that exports the flash as physical without any
 * mapping and garbage collection as it will be taken care of.
 */
static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct openssd *os;

	// Which device it should map onto?
	if (argc != 1) {
		ti->error = "Only argument for block device allowed.";
		return -EINVAL;
	}

	os = kmalloc(sizeof(*os), GFP_KERNEL);
	if (os == NULL) {
		ti->error = "dm-openssd: Cannot allocate openssd context";
		return -ENOMEM;
	}

	os->trans_map = vmalloc(sizeof(struct openssd_map)/* *512 */ * 512*16); /* Remove constant with number of logical to
									  physical address mappings that should be stored. */
	if (os->trans_map == NULL) {
		ti->error = "dm-openssd: Cannot allocate openssd mapping context";
		kfree(os);
		return -ENOMEM;
	}

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &os->dev)) {
		ti->error = "dm-openssd: Device lookup failed";
		goto bad;
	}

	os->ti = ti;
	ti->private = os;

	/* Initialize pools. */
	openssd_pool_init(os, ti);
	DMINFO("dm-openssd successful load");

	return 0;

bad:
	vfree(os->trans_map);
	kfree(os);
	return -EINVAL;
}

static void openssd_dtr(struct dm_target *ti)
{
	struct openssd *os = (struct openssd *) ti->private;
	struct openssd_pool *pool;
	int i;

	dm_put_device(ti, os->dev);

	ssd_for_each_pool(os, pool, i)
		kfree(pool->blocks);

	kfree(os->pools);
	kfree(os->aps);

	vfree(os->trans_map);

	kfree(os);

	DMINFO("dm-openssd successful unload");
}

static int openssd_map(struct dm_target *ti, struct bio *bio,
		    union map_info *map_context)
{
	struct openssd *os;
	DMINFO("Accessing: %lu size: %u", bio->bi_sector, bio->bi_size);

	/* do hint */
	openssd_bio_hints(ti, bio);

	/* accepted bio, don't make new request */
	os = (struct openssd *) ti->private;
	bio->bi_bdev = os->dev->bdev;
	generic_make_request(bio);
	return DM_MAPIO_SUBMITTED;
}

static int openssd_user_hint_cmd(struct openssd *os, hint_data_t __user *uhint)
{
	hint_data_t* hint_data;
	DMINFO("send user hint");

	/* allocate hint_data */
	hint_data = kmalloc(sizeof(hint_data_t), GFP_ATOMIC);
	if (hint_data == NULL) {
		DMERR("hint_data_t kmalloc failed");  
		return;
	}

    // copy hint data from user space
	if (copy_from_user(hint_data, uhint, sizeof(uhint)))
		return -EFAULT;

	// send hint to device
	return openssd_send_hint(os->ti, hint_data);
}
static int openssd_ioctl(struct dm_target *ti, unsigned int cmd,
			             unsigned long arg)
{
	struct openssd *os;
	struct dm_dev *dev;

	os = (struct openssd *) ti->private;
	dev = os->dev;

    DMDEBUG("got ioctl %x\n", cmd);
	switch (cmd) {
	    case OPENSSD_IOCTL_ID:
		    return 12345678; // TODO: what do we do here?
	    case OPENSSD_IOCTL_SUBMIT_HINT:
		    return openssd_user_hint_cmd(os, (hint_data_t __user *)arg);
	    default:
			// general ioctl to device
			printk("generic ioctl. forward to device\n");
	        return __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);
	}
}

static int openssd_endio(struct dm_target *ti,
		      struct bio *bio, int err,
		      union map_info *map_context)
{
	return 0;
}

static void openssd_postsuspend(struct dm_target *ti)
{
}

static int openssd_status(struct dm_target *ti, status_type_t type,
		       char *result, unsigned maxlen)
{
	return 0;
}

static int openssd_iterate_devices(struct dm_target *ti,
				iterate_devices_callout_fn fn, void *data)
{
	return 0;
}

static void openssd_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
}

static struct target_type openssd_target = {
	.name = "openssd",
	.version = {0, 0, 1},
	.module	= THIS_MODULE,
	.ctr = openssd_ctr,
	.dtr = openssd_dtr,
	.map = openssd_map,
	.ioctl = openssd_ioctl,
	//.end_io = openssd_endio,
	//.postsuspend = openssd_postsuspend,
	//.status = openssd_status,
	//.iterate_devices = openssd_iterate_devices,
	//.io_hints = openssd_io_hints,
};

static int __init dm_openssd_init(void)
{
	int r;

	r = dm_register_target(&openssd_target);

	return r;
}

static void dm_openssd_exit(void)
{
	dm_unregister_target(&openssd_target);
}

module_init(dm_openssd_init);
module_exit(dm_openssd_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper openssd target");
MODULE_AUTHOR("Matias Bjørling <mb@silverwolf.dk>");
MODULE_LICENSE("GPL");
