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
#include <linux/list_sort.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/delay.h>
#include <linux/time.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <linux/mempool.h>

#define DM_MSG_PREFIX "openssd"
#define APS_PER_POOL 1 /* Number of append points per pool. We assume that accesses within 
						  a pool is serial (NAND flash / PCM / etc.) */
#define SERIALIZE_AP_ACCESS 1 /* If enabled, we delay bios on each ap to run serialized. */
#define LTOP_EMPTY -1

/* Sleep timings before simulating device specific storage (in us)*/
#define TIMING_READ 25
#define TIMING_WRITE 500
#define TIMING_ERASE 1500

/* Run GC every X seconds */
#define GC_TIME 10
/* Run only GC is less than 1/X blocks are free */
#define GC_LIMIT_INVERSE 2

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
	 * BLOCK_PAGE_COUNT must be a power of two.
	 */
#define DEBUG 1

#define DEVICE_PAGE_SIZE 512	/* The minimum page size we communicate with to the physical disk */
#define EXPOSED_PAGE_SIZE 4096	/* The page size that we expose to the operating system */
#define FLASH_PAGE_SIZE 8196	/* The size of the physical flash page */

#define POOL_COUNT 8
#define POOL_BLOCK_COUNT 32
#define BLOCK_PAGE_COUNT 64

/*---------------------
 * Swap hints. TODO: all this should move to configuration files, etc.
 *
 * different timings, roughly based on "Harey Tortoise" paper (TODO: ratio is actually 4.8 on average)
 *------------------- */
#define TIMING_WRITE_FAST (TIMING_WRITE / 2)
#define TIMING_WRITE_SLOW (TIMING_WRITE * 2)

#define NR_HOST_PAGES_IN_FLASH_PAGE (FLASH_PAGE_SIZE / EXPOSED_PAGE_SIZE)
#define NR_PHY_IN_LOG (EXPOSED_PAGE_SIZE / 512)

struct openssd_dev_conf {
	unsigned short int flash_block_size; /* the number of flash pages per block */
	unsigned short int flash_page_size;  /* the flash page size in bytes */
	unsigned int num_blocks;	   /* the number of blocks addressable by the mapped SSD. */
};

/* Pool descriptions */
struct openssd_pool_block {
	struct {
		spinlock_t lock;
		unsigned int next_page; /* points to the next writable flash page within a block */
		unsigned char next_offset; /* if a flash page can have multiple host pages, 
									   fill up the flash page before going to the next 
									   writable flash page */
		unsigned int nr_invalid_pages;
		bool is_full;

		/* no need to sync. Move down if it overflow the cacheline */
		struct openssd_pool *parent;
		unsigned int id;
	} ____cacheline_aligned_in_smp;

	struct list_head list;
	struct list_head prio;

	struct page **data;
	atomic_t data_size; /* data pages inserted into data variable */
	atomic_t data_cmnt_size; /* data pages committed to stable storage */
};

struct openssd_addr {
	sector_t addr;
	struct openssd_pool_block *block;
};

struct openssd_pool {
	/* Pool block lists */
	struct {
		spinlock_t lock;
		struct list_head used_list;
		struct list_head free_list;
		struct list_head prio_list;
	} ____cacheline_aligned_in_smp;
	unsigned long phy_addr_start;	/* References the physical start block */
	unsigned int phy_addr_end;		/* References the physical end block */

	unsigned int nr_blocks;			/* Derived value from end_block - start_block. */
	unsigned int nr_free_blocks;	/* Number of unused blocks */

	struct openssd_pool_block *blocks;
};

/*
 * openssd_ap. ap is an append point. A pool can have 1..X append points attached.
 * An append point has a current block, that it writes to, and when its full, it requests
 * a new block, of which it continues its writes.
 */
struct openssd_ap {
	spinlock_t lock;
	struct openssd *parent;
	struct openssd_pool *pool;
	struct openssd_pool_block *cur;

	/* Timings used for end_io waiting */
	unsigned long t_read;
	unsigned long t_write;
	unsigned long t_erase;

	/* Postpone issuing I/O if append point is active */
	atomic_t is_active;
	struct work_struct waiting_ws;
	spinlock_t waiting_lock;
	struct bio_list waiting_bios;

	unsigned long io_delayed;
	unsigned long io_accesses[2];
};

struct openssd;

typedef sector_t (map_ltop_fn)(struct openssd *, sector_t, struct openssd_pool_block **);
typedef struct openssd_addr *(lookup_ltop_fn)(struct openssd *, sector_t);

enum deploy_hint_flags {
	HINT_NONE	= 0 << 0, /* No hints applied */
	HINT_SWAP	= 1 << 0, /* Swap aware hints. Detected from partition offset */
	HINT_IOCTL	= 1 << 1, /* IOCTL aware hints. Applications may submit direct hints */
};

/* Configuration of hints that are deployed within the openssd instance */
#define DEPLOYED_HINTS /*(HINT_NONE)*/ (HINT_SWAP | HINT_IOCTL)

/* Main structure */
struct openssd {
	struct dm_dev *dev;
	struct dm_target *ti;
	uint32_t sector_size;

	/* Simple translation map of logical addresses to physical addresses. The 
	 * logical addresses is known by the host system, while the physical
	 * addresses are used when writing to the disk block device. */
	struct openssd_addr *trans_map;
	/* also store a reverse map for garbage collection */
	sector_t *rev_trans_map;

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

	mempool_t *per_bio_pool;

	int nr_pools;
	int nr_aps;
	int nr_aps_per_pool;

	unsigned long nr_pages;

	unsigned int next_collect_pool;
	/* FTL interface */
	map_ltop_fn *map_ltop;
	lookup_ltop_fn *lookup_ltop;

	/* Write strategy variables. Move these into each for structure for each 
	 * strategy */
	atomic_t next_write_ap; /* Whenever a page is written, this is updated to point
							   to the next write append point */

	bool serialize_ap_access;		/* Control accesses to append points in the host.
							 * Enable this for devices that doesn't have an
							 * internal queue that only lets one command run
							 * at a time within an append point 
							*/
	struct workqueue_struct *kbiod_wq;

	struct task_struct *kt_openssd; /* handles gc and any other async work */

	/* Hint related*/
	unsigned int hint_flags;
	char fast_page_block_map[BLOCK_PAGE_COUNT];
	spinlock_t hintlock;
	struct list_head hintlist;
};

static struct kmem_cache *_per_bio_cache;

struct per_bio_data {
	struct openssd_ap *ap;
	struct timeval start_tv;
	sector_t physical_addr;

	// Hook up for our overwritten bio fields
	bio_end_io_t *bi_end_io; 
	void *bi_private;
};

static inline struct per_bio_data *get_per_bio_data(struct bio *bio)
{
	return (struct per_bio_data *) bio->bi_private;
}

static struct per_bio_data *alloc_decorate_per_bio_data(struct openssd *os, struct bio *bio)
{
	struct per_bio_data *pb = mempool_alloc(os->per_bio_pool, GFP_NOIO);

	if (!pb)
		return NULL;

	pb->bi_end_io = bio->bi_end_io;
	pb->bi_private = bio->bi_private;

	bio->bi_private = pb;

	return pb;
}

static void dedecorate_bio(struct per_bio_data *pb, struct bio *bio)
{
	bio->bi_private = pb->bi_private;
	bio->bi_end_io = pb->bi_end_io;
}

static void free_per_bio_data(struct openssd *os, struct bio *bio)
{
	struct per_bio_data *pb = bio->bi_private;
	mempool_free(pb, os->per_bio_pool);
}

/* the block with highest number of invalid pages, will be in the beginning of the list */
static int block_prio_sort_cmp(void *priv, struct list_head *lh_a, struct list_head *lh_b)
{
	struct openssd_pool_block *a = list_entry(lh_a, struct openssd_pool_block, prio);
	struct openssd_pool_block *b = list_entry(lh_b, struct openssd_pool_block, prio);

	if (a->nr_invalid_pages == b->nr_invalid_pages)
		return 0;

	return a->nr_invalid_pages < b->nr_invalid_pages;
}

static inline sector_t block_to_addr(struct openssd_pool_block *block)
{
	return (block->id * BLOCK_PAGE_COUNT);
}

static inline struct openssd_ap *block_to_ap(struct openssd *os, struct openssd_pool_block *block)
{
	unsigned int ap_idx, div, mod;

	div = block->id / POOL_BLOCK_COUNT;
	mod = block->id % POOL_BLOCK_COUNT;
	ap_idx = div + (mod / (POOL_BLOCK_COUNT / APS_PER_POOL));

	return &os->aps[ap_idx];
}

static void openssd_delayed_bio_submit(struct work_struct *work)
{
	struct openssd_ap *ap = container_of(work, struct openssd_ap, waiting_ws);
	struct bio *bio;

	spin_lock(&ap->waiting_lock);
	bio = bio_list_pop(&ap->waiting_bios);
	spin_unlock(&ap->waiting_lock);

	generic_make_request(bio);
}

static void openssd_update_mapping(struct openssd *os,  sector_t l_addr,
						   sector_t p_addr, struct openssd_pool_block *p_block)
{
	struct openssd_addr *l;

	if(l_addr >= os->nr_pages || p_addr >= os->nr_pages){
		DMERR("update_mapping: illegal address l_addr %ld p_addr %ld", l_addr, p_addr);
		return;
	}
	BUG_ON(l_addr >= os->nr_pages);
	BUG_ON(p_addr >= os->nr_pages);

	l = &os->trans_map[l_addr];
	if (l->block) {
		BUG_ON(l->block->nr_invalid_pages == BLOCK_PAGE_COUNT * NR_HOST_PAGES_IN_FLASH_PAGE);
		l->block->nr_invalid_pages++;
	}

	l->addr = p_addr;
	l->block = p_block;

	/* Physical -> Logical address */
	os->rev_trans_map[p_addr] = l_addr;
}

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append point, we store it within the used_list.
 * We then move it back when its free to be used by another append point.
 *
 * The newly acclaimed block is always added to the back of user_list. As we assume
 * that the start of used list is the oldest block, and therefore higher probability
 * of invalidated pages.
 */
static struct openssd_pool_block *openssd_pool_get_block(struct openssd_pool *pool)
{
	struct openssd_pool_block *block = NULL;
	void *data;

	data = kmalloc((FLASH_PAGE_SIZE * BLOCK_PAGE_COUNT) / PAGE_SIZE * sizeof(struct page *), GFP_NOIO);

	if (!data)
		return NULL;

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) 
	{
		spin_unlock(&pool->lock);
		return NULL;
	}

	block = list_first_entry(&pool->free_list, struct openssd_pool_block, list);
	list_move_tail(&block->list, &pool->used_list);

	pool->nr_free_blocks--;

	spin_unlock(&pool->lock);

	block->data = data;

	return block;
}

/* requires pool->lock taken */
static inline void openssd_reset_block(struct openssd_pool_block *block)
{
	BUG_ON(!block);

	spin_lock(&block->lock);
	block->next_page = 0;
	block->next_offset = 0;
	block->nr_invalid_pages = 0;
	block->is_full = false;
	atomic_set(&block->data_size, 0);
	atomic_set(&block->data_cmnt_size, 0);
	kfree(block->data);
	spin_unlock(&block->lock);
}

/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby provide
 * simple (naive) wear-leveling.
 */
static void openssd_pool_put_block(struct openssd_pool_block *block)
{
	struct openssd_pool *pool = block->parent;

	openssd_reset_block(block);

	spin_lock(&pool->lock);

	list_move_tail(&block->list, &pool->free_list);

	pool->nr_free_blocks++;
	spin_unlock(&pool->lock);
}

static sector_t openssd_get_physical_page(struct openssd_pool_block *block)
{
	sector_t addr = -1;

	spin_lock(&block->lock);

	if (block->next_page + block->next_offset == BLOCK_PAGE_COUNT * NR_HOST_PAGES_IN_FLASH_PAGE)
		goto get_done;

	/* If there is multiple host pages within a flash page, we add the 
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE - 1) {
		block->next_offset = 0;
		block->next_page++;
	}

	addr = block_to_addr(block) + block->next_page + block->next_offset;
	block->next_offset++;

	if (addr == (BLOCK_PAGE_COUNT * NR_HOST_PAGES_IN_FLASH_PAGE) - 1)
		block->is_full = true;

get_done:
	spin_unlock(&block->lock);
	return addr;
}

static void openssd_set_ap_cur(struct openssd_ap *ap, struct openssd_pool_block *block)
{
	spin_lock(&ap->lock);
	ap->cur = block;
	spin_unlock(&ap->lock);
}

static void openssd_erase_block(struct openssd_pool_block *block)
{
	/* Send erase command to device. */
}

static void openssd_move_valid_pages(struct openssd *os, struct openssd_pool_block *target_block)
{
	//sector_t saddr = block_to_addr(target_block);
}

static void openssd_print_total_blocks(struct openssd *os)
{
	struct openssd_pool *pool;
	unsigned int total = 0;
	int i;

	ssd_for_each_pool(os, pool, i)
		total += pool->nr_free_blocks;
	DMINFO("Total free blocks: %u", total);
}

static void openssd_gc_collect(struct openssd *os)
{
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	unsigned int nr_blocks_need;
	int pid, pid_start;
	int max_collect = os->nr_pools / 2;

	//openssd_print_total_blocks(os);

	while (max_collect) {
		block = NULL;
		/* Iterate the pools once to look for pool that has a block to be freed. */
		pid = os->next_collect_pool % os->nr_pools;
		pid_start = pid;
		do {
			pool = &os->pools[pid];

			nr_blocks_need = pool->nr_blocks;
			do_div(nr_blocks_need, GC_LIMIT_INVERSE);

			if (nr_blocks_need >= pool->nr_free_blocks) {
				list_sort(NULL, &pool->prio_list, block_prio_sort_cmp);
				block = list_first_entry(&pool->prio_list, struct openssd_pool_block, prio);

				openssd_erase_block(block);
				openssd_pool_put_block(block);

				break;
			}

			pid++;
			pid %= os->nr_pools;
		} while (pid_start != pid);

		os->next_collect_pool++;
		max_collect--;
	}
}

static int openssd_kthread(void *data)
{
	struct openssd *os = (struct openssd *)data;
	BUG_ON(!os);

	while (!kthread_should_stop()) {

		openssd_gc_collect(os);

		schedule_timeout_uninterruptible(GC_TIME * HZ); 
	}

	return 0;
}

// iterate hints list, and check if lba of current req is covered by some hint
hint_info_t* openssd_find_hint(struct openssd *os, sector_t logical_addr, bool is_write)
{
	hint_info_t *hint_info;
	struct list_head *node;

	//DMINFO("find hint for lba %ld is_write %d", logical_addr, is_write);
	spin_lock(&os->hintlock);
	/*see if hint is already in list*/
	list_for_each(node, &os->hintlist){
		hint_info = list_entry(node, hint_info_t, list_member);
		//DMINFO("hint start_lba=%d count=%d", hint_info->hint.start_lba, hint_info->hint.count);
		//continue;
		/* verify lba covered by hint*/
		if (is_hint_relevant(logical_addr, hint_info, is_write)) {
                        DMINFO("found hint for lba %ld",logical_addr);
			hint_info->processed++;	
			spin_unlock(&os->hintlock);
			return hint_info;
		}
	}
	spin_unlock(&os->hintlock);
	//DMINFO("no hint found for %s lba %ld", (is_write)?"WRITE":"READ",logical_addr);

	return NULL;
}

static int openssd_get_fast_page_id(struct openssd *os, struct openssd_pool_block *block)
{
	int page_id = -1;

	// access block next_page in protected manner
	// TODO: now that this access is protected by spinlock (to avoid race condition with
	//       openssd_get_page_id, is the atomic_XXX_return part redundant?
	spin_lock(&block->lock);
	page_id = --block->next_page;

	// block exhausted
	if (page_id >= BLOCK_PAGE_COUNT){
		//DMINFO("block exhausted");
		page_id = -1;
		goto fast_done;
	}

	// slow page
	if (!os->fast_page_block_map[page_id]){
		//DMINFO("block page_id=%d is slow", page_id);
		block->next_page--;
		page_id = -1;
		goto fast_done;
	}

	DMINFO("block page_id=%d is fast", page_id);
fast_done:
	spin_unlock(&block->lock);
	return page_id;
}

fclass file_classify(struct bio_vec* bvec) 
{
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

// no real sending for now, in prototype just put it directly in FTL's hints list
static int openssd_send_hint(struct openssd *os, hint_data_t *hint_data)
{
	int i;
	hint_info_t* hint_info;

	DMINFO("first %s hint count=%d lba=%d fc=%d", 
			CAST_TO_PAYLOAD(hint_data)->is_write ? "WRITE" : "READ",
			CAST_TO_PAYLOAD(hint_data)->count,
			INO_HINT_FROM_DATA(hint_data, 0).start_lba,
			INO_HINT_FROM_DATA(hint_data, 0).fc);

	if(!os->hint_flags)
		goto send_done;

	// insert to hints list
	for(i = 0; i < CAST_TO_PAYLOAD(hint_data)->count; i++){
		hint_info = kmalloc(sizeof(hint_info_t), GFP_KERNEL);
		if (!hint_info) {
			DMERR("can't allocate hint info");
			return -ENOMEM;
		}
		memcpy(&hint_info->hint, &INO_HINT_FROM_DATA(hint_data, i), sizeof(ino_hint_t));
		hint_info->processed = 0;
		hint_info->is_write  = CAST_TO_PAYLOAD(hint_data)->is_write;
		hint_info->is_swap   = CAST_TO_PAYLOAD(hint_data)->is_swap;

		DMINFO("about to add hint_info to list. %s %s", 
				(CAST_TO_PAYLOAD(hint_data)->is_swap) ? "SWAP" : "REGULAR", 
				(CAST_TO_PAYLOAD(hint_data)->is_write) ? "WRITE" : "READ");

		spin_lock(&os->hintlock);
		list_add_tail(&hint_info->list_member, &os->hintlist);
		spin_unlock(&os->hintlock);
	}

send_done:
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
static void openssd_bio_hints(struct openssd *os, struct bio *bio)
{
	hint_data_t *hint_data;
	fclass fc = FC_EMPTY;
	unsigned ino = -1;
	struct page *bv_page;
	struct address_space *mapping;
	struct inode *host;
	struct bio_vec *bvec;
	uint32_t sector_size = os->sector_size;
	uint32_t sectors_count = 0;
	uint32_t lba = 0, bio_len = 0, hint_idx;
	unsigned long prev_ino = -1, first_sector = -1;
	int i, ret;
	bool is_write = 0;

	return;
	/* can classify only writes*/
	switch(bio_rw(bio)) {
		case READ:
		case READA:
			/* read/readahead*/
			break;
		case WRITE:
			is_write = 1;
			break;
	}

	// get lba and sector count
	lba = bio->bi_sector;
	sectors_count = bio->bi_size / sector_size;

	/* allocate hint_data */
	hint_data = kzalloc(sizeof(hint_data_t), GFP_NOIO);
	if (!hint_data) {
		DMERR("hint_data_t kmalloc failed");
		return;
	}

	CAST_TO_PAYLOAD(hint_data)->lba = lba;
	CAST_TO_PAYLOAD(hint_data)->sectors_count = sectors_count;
	CAST_TO_PAYLOAD(hint_data)->is_write = is_write;
	ino = -1;
	DMINFO("%s lba=%d sectors_count=%d",
			is_write ? "WRITE" : "READ",
			lba, sectors_count);
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

		if (mapping && ((unsigned long)mapping & PAGE_MAPPING_ANON) == 0) {
			host = mapping->host;
			if (!host) {
				DMCRIT("page without mapping->host. shouldn't happen");
				bio_len += bvec[0].bv_len;
				continue; // no host
			}

			prev_ino = ino;
			ino = host->i_ino;

			if(!host->i_sb || !host->i_sb->s_type || !host->i_sb->s_type->name){
				DMINFO("not related to file system");
				bio_len += bvec[0].bv_len;
				continue;
			}

			if(!ino) {
				DMINFO("not inode related");
				bio_len += bvec[0].bv_len;
				continue;
			}
			//if(bvec[0].bv_offset) 
			//   DMINFO("bv_page->index %d offset %d len %d", bv_page->index, bvec[0].bv_offset, bvec[0].bv_len);

			/* classify if we can.
			 * can only classify writes to file's first sector */
			fc = FC_EMPTY;
			if (is_write && bv_page->index == 0 && bvec[0].bv_offset ==0) {
				// should be first sector in file. classify
				first_sector = lba + (bio_len / sector_size);
				fc = file_classify(&bvec[0]); 
			}

			/* change previous hint, unless this is a new inode
			   and then simply increment count in existing hint */
			if(prev_ino == ino) {
				hint_idx = CAST_TO_PAYLOAD(hint_data)->count - 1;
				if(INO_HINT_FROM_DATA(hint_data, hint_idx).ino != ino) {
					DMERR("updating hint of wrong ino (ino=%u expected=%lu)", ino,
						INO_HINT_FROM_DATA(hint_data, hint_idx).ino);            
					bio_len += bvec[0].bv_len;
					continue;
				}

					INO_HINT_FROM_DATA(hint_data, hint_idx).count += bvec[0].bv_len / sector_size;
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
					is_write ? "WRITE":"READ",
					ino, 
					lba + (bio_len / sector_size),
					(fc == FC_VIDEO_SLOW) ? "VIDEO" : (fc == FC_EMPTY) ? "EMPTY" : "UNKNOWN",
					bvec[0].bv_len / sector_size, 
					CAST_TO_PAYLOAD(hint_data)->count+1);

				// add new hint to hint_data. lba count=bvec[0].bv_len / sector_size, will add more later on
				INO_HINT_SET(hint_data, CAST_TO_PAYLOAD(hint_data)->count, 
					ino, lba + (bio_len / sector_size), bvec[0].bv_len / sector_size, fc);
				CAST_TO_PAYLOAD(hint_data)->count++;
			}
		}

		// increment len
		bio_len += bvec[0].bv_len;
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
	if(CAST_TO_PAYLOAD(hint_data)->count == 0) {
		//hint_log("request with no file data");
		goto done;
	}

	/* non-empty hint_data, send to device */
	//hint_log("hint count=%u. send to hint device", CAST_TO_PAYLOAD(hint_data)->count);
	ret = openssd_send_hint(os, hint_data);

	if (ret != 0)
		DMINFO("openssd_send_hint error %d", ret);

done:
	kfree(hint_data);
}

void openssd_ctr_swap_hint(struct openssd *os){
	int i;

	for(i=0;i<BLOCK_PAGE_COUNT;i++) os->fast_page_block_map[i] = 0;

	// first four are fast
	for(i=0;i<4;i++){
		os->fast_page_block_map[i] = 1;
	}

	// in between, its slow-slow-fast-fast-slow-slow...
	for(i=6;i<BLOCK_PAGE_COUNT-4;){
		os->fast_page_block_map[i] = os->fast_page_block_map[i+1] = 1;
		i+=4;
	}
}

static int openssd_user_hint_cmd(struct openssd *os, hint_data_t __user *uhint)
{
	hint_data_t* hint_data;
	DMINFO("send user hint");

	/* allocate hint_data */
	hint_data = kmalloc(sizeof(hint_data_t), GFP_KERNEL);
	if (hint_data == NULL) {
		DMERR("hint_data_t kmalloc failed");  
		return -ENOMEM;
	}

    // copy hint data from user space
	if (copy_from_user(hint_data, uhint, sizeof(hint_data_t)))
		return -EFAULT;

	// send hint to device
	return openssd_send_hint(os, hint_data);
}

static int openssd_kernel_hint_cmd(struct openssd *os, hint_data_t *khint)
{
    // send hint to device
    // TODO: do we need to free khint here? or is it freed by block layer?
    return openssd_send_hint(os, khint);
}

static struct openssd_addr *openssd_lookup_ltop(struct openssd *os, sector_t logical_addr)
{
	// TODO: during GC or w-r-w we may get a translation for an old page.
	//       do we care enough to enforce some serializibilty in LBA accesses?
	return &os->trans_map[logical_addr];
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for the
 * next write to the disk.
 *
 * Returns the physical mapped address.
 */
static sector_t openssd_map_ltop_rr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block)
{
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	int ap_id = atomic_inc_return(&os->next_write_ap) % os->nr_aps;
	int page_id;
	sector_t physical_addr;

	ap = &os->aps[ap_id];
	block = ap->cur;

	page_id = openssd_get_physical_page(block);
	while (page_id < 0) {
		block = openssd_pool_get_block(block->parent);
		if (!block)
			return -1;

		openssd_set_ap_cur(ap, block);
		page_id = openssd_get_physical_page(block);
	}

	physical_addr = block_to_addr(block) + page_id;
	DMINFO("logical_addr=%ld physical_addr=%ld (page_id=%d)", logical_addr, physical_addr, page_id);

	openssd_update_mapping(os, logical_addr, physical_addr, block);

	(*ret_victim_block) = block;
	return physical_addr;
}

/* Swap-proned Logical to physical address translation.
 *
 * If swap write, use simple fast page allocation - find some append point whose next page is fast. 
 * Then update the ap for the next write to the disk.
 * If no reelvant ap found, or non-swap write - resort to normal allocation
 */
static sector_t openssd_map_swap_hint_ltop_rr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block)
{
	hint_info_t* hint_info;
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	int ap_id;
	int page_id = -1, i = 0;
	sector_t physical_addr;

	// Check if there is a hint for relevant sector
	// if not, resort to openssd_map_ltop_rr
	if((hint_info = openssd_find_hint(os, logical_addr, 1)) == NULL)
		return openssd_map_ltop_rr(os, logical_addr, ret_victim_block);


	/* iterate all ap's and find fast page
	 * TODO 1) should loop over append points (when we have more than 1 AP/pool)
	 *      2) is it really safe iterating pools like this? do we need to lock anything else?
	 *      3) add test for active_ap->is_active? or do we not care?
	 */
	//DMINFO("find fast page for hinted swap write");
	while (page_id < 0 && i < POOL_COUNT) {
		ap_id = atomic_inc_return(&os->next_write_ap) % os->nr_aps;
		//DMINFO("%d) ap_id %d", i,  ap_id);
		ap = &os->aps[ap_id];
		block = ap->cur;

		page_id = openssd_get_fast_page_id(os, block);
		i++;
	}

	// processed entire hint
	// Note: for swap hints we can actually avoid this lock, and free after processed++ in
	//       openssd_find_hint(), but it would clutter its code for swap-specific stuff
	spin_lock(&os->hintlock);
	if(hint_info->processed == hint_info->hint.count){
		//DMINFO("delete swap hint");
		list_del(&hint_info->list_member);
		kfree(hint_info);
	}
	spin_unlock(&os->hintlock);

	// no fast page available, resort to openssd_map_ltop_rr
	if(page_id < 0){
		//DMINFO("write lba %ld to slow page", logical_addr);
		return openssd_map_ltop_rr(os, logical_addr, ret_victim_block);
	}

	//DMINFO("fast page_id=%d", page_id);

	physical_addr = block_to_addr(block) + page_id;

	openssd_update_mapping(os, logical_addr, physical_addr, block);

	(*ret_victim_block) = block;
	//DMINFO("write lba %ld to fast page %ld", logical_addr, physical_addr);
	return physical_addr;
}

static void openssd_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb;
	struct openssd_ap *ap;
	struct openssd *os;
	struct timeval end_tv;
	unsigned long diff, dev_wait, total_wait = 0;

	if (err) {
		bio_endio(bio, err);
		return;
	}

	pb = get_per_bio_data(bio);

	ap = pb->ap;
	os = ap->parent;

	if (pb->physical_addr == LTOP_EMPTY)
		goto done;

	if (bio_data_dir(bio) == WRITE)
		dev_wait = ap->t_write;
	else
		dev_wait = ap->t_read;

	if ((os->hint_flags & HINT_SWAP) && bio_data_dir(bio) == WRITE) {
		// TODO: consider dev_wait to be part of per_bio_data?
		if(os->fast_page_block_map[os->trans_map[bio->bi_sector].addr % BLOCK_PAGE_COUNT])
			dev_wait = TIMING_WRITE_FAST;
		else
			dev_wait = TIMING_WRITE_SLOW;
	}

	if (dev_wait) {
		do_gettimeofday(&end_tv);
		diff = end_tv.tv_usec - pb->start_tv.tv_usec;
		if (dev_wait > diff)
			total_wait = dev_wait - diff;

		if (total_wait > 50) {
			udelay(total_wait);
		}
	}

	// Remember that the IO is first officially finished from here 
	if (bio_list_peek(&ap->waiting_bios))
		queue_work(os->kbiod_wq, &ap->waiting_ws);
	else
		atomic_set(&ap->is_active, 0);

done:
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	free_per_bio_data(os, bio);
}

static void openssd_end_read_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of reads 
	 * Remember that bio->bi_end_io is overwritten during bio_split() 
	 */
	openssd_endio(bio, err);
}

static void openssd_end_write_bio(struct bio *bio, int err)
{
	/* FIXME: Implement error handling of writes */
	openssd_endio(bio, err);
}

static void openssd_submit_bio(int rw, struct bio *bio, struct openssd_ap *ap)
{
	struct openssd *os = ap->parent;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(os, bio);
	pb->ap = ap;

	if (rw == WRITE)
		bio->bi_end_io = openssd_end_write_bio;
	else
		bio->bi_end_io = openssd_end_read_bio;

	/* setup timings - remember overhead. */
	do_gettimeofday(&pb->start_tv);

	if (os->serialize_ap_access && atomic_read(&ap->is_active)) {
		spin_lock(&ap->waiting_lock);
		ap->io_delayed++;
		bio_list_add(&ap->waiting_bios, bio);
		spin_unlock(&ap->waiting_lock);
	} else {
		atomic_inc(&ap->is_active);
	}

	// We allow counting to be semi-accurate as theres no locking for accounting.
	ap->io_accesses[bio_data_dir(bio)]++;

	submit_bio(rw, bio);
}
static void openssd_fill_bio_and_end(struct bio *bio)
{
	printk("no data\n");
	zero_fill_bio(bio);
	bio_endio(bio, 0);
}

static int openssd_handle_read(struct openssd *os, struct bio *bio)
{
	struct bio *exec_bio, *split_bio;
	struct bio_pair *bp;
	struct bio_vec *bv;
	struct openssd_addr *phys;
	sector_t log_addr;
	int i;

	if (bio_sectors(bio) > NR_PHY_IN_LOG) {
//		printk("split\n");
		split_bio = bio;
		bio_for_each_segment(bv, bio, i) {
			bp = bio_split(split_bio, NR_PHY_IN_LOG);

			exec_bio = &bp->bio1;
			split_bio = &bp->bio2;

			log_addr = exec_bio->bi_sector / NR_PHY_IN_LOG;
			phys = os->lookup_ltop(os, log_addr);

			if (!phys->block) {
				openssd_fill_bio_and_end(bio);
				return 0;
			}

			exec_bio->bi_sector = phys->addr;

//			printk("exec_bio addr: %lu bi_sectors: %u orig_addr: %lu\n", exec_bio->bi_sector, bio_sectors(exec_bio), bio->bi_sector);
			openssd_submit_bio(READ, exec_bio, block_to_ap(os, phys->block));
		}
	} else {
		log_addr = bio->bi_sector / NR_PHY_IN_LOG;
		phys = os->lookup_ltop(os, log_addr);

		if (!phys->block) {
			openssd_fill_bio_and_end(bio);
			return 0;
		}


//		printk("bio addr: %lu bi_sectors: %u\n", bio->bi_sector, bio_sectors(bio));

		openssd_submit_bio(READ, bio, block_to_ap(os, phys->block));
	}

	return 0;
}

static int openssd_handle_write(struct openssd *os, struct bio *bio)
{
	struct openssd_pool_block *victim_block = NULL;
	struct bio_vec *bv;
	struct bio *issue_bio;
	sector_t logical_addr, physical_addr;
	int i, bv_i, size;

	bio_for_each_segment(bv, bio, i) {
		unsigned int idx;

		if (bv->bv_len != PAGE_SIZE && bv->bv_offset != 0) {
			printk("Doesn't yet support IO sizes other than system page size. (bv_len %u bv_offset %u)", bv->bv_len, bv->bv_offset);
			return -ENOSPC;
		}

		logical_addr = (bio->bi_sector / (EXPOSED_PAGE_SIZE / 512)) + i;
		physical_addr = os->map_ltop(os, logical_addr, &victim_block);

		//DMINFO("Logical: %lu Physical: %lu OS Sector addr: %u Sectors: %u Size: %u", logical_addr, physical_addr, bio->bi_sector, bio_sectors(bio), bio->bi_size);
		if (physical_addr == -1) {
			DMERR("No more physical addresses");
			return -ENOSPC;
		}

		idx = physical_addr % (FLASH_PAGE_SIZE * BLOCK_PAGE_COUNT / PAGE_SIZE);
		victim_block->data[idx] = bv->bv_page;
		size = atomic_inc_return(&victim_block->data_size);

		//FIXME: Assumes 4K mapping
		/* Writes whenever a flash page is full */
		if (size % (FLASH_PAGE_SIZE / PAGE_SIZE) == 0) {
			//FIXME: can fail
			issue_bio = bio_alloc(GFP_NOIO, 2);
			issue_bio->bi_bdev = bio->bi_bdev;
			issue_bio->bi_sector = ((physical_addr - 1) * 8);

			for (bv_i = 0; bv_i < (FLASH_PAGE_SIZE / PAGE_SIZE); bv_i++) {
				unsigned int idx_to_write = size - (FLASH_PAGE_SIZE / PAGE_SIZE) + bv_i;
				bio_add_page(issue_bio, victim_block->data[idx_to_write], PAGE_SIZE, 0);
			}
			openssd_submit_bio(WRITE, issue_bio, block_to_ap(os, victim_block));
		}
	}

	/* do hint */
	openssd_bio_hints(os, bio);

	bio_endio(bio, 0);

	return 0;
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
		    return 12345678; // TODO: anything else?
	    case OPENSSD_IOCTL_SUBMIT_HINT:
		    return openssd_user_hint_cmd(os, (hint_data_t __user *)arg);
	    case OPENSSD_IOCTL_KERNEL_HINT:
		    return openssd_kernel_hint_cmd(os, (hint_data_t*)arg);
	    default:
            // general ioctl to device
            printk("generic ioctl. forward to device\n");
	        return __blkdev_driver_ioctl(dev->bdev, dev->mode, cmd, arg);
	}
}

static int openssd_map(struct dm_target *ti, struct bio *bio)
{
	struct openssd *os = ti->private;

	bio->bi_bdev = os->dev->bdev;

	if (bio_data_dir(bio) == WRITE)
		openssd_handle_write(os, bio);
	else
		openssd_handle_read(os, bio);

	return DM_MAPIO_SUBMITTED;
}

static void openssd_status(struct dm_target *ti, status_type_t type,
			 unsigned status_flags, char *result, unsigned maxlen) 
{
	struct openssd *os = ti->private;
	struct openssd_ap *ap;
	int i, sz = 0;

	switch(type) {
	case STATUSTYPE_INFO:
		DMEMIT("Use table information");
		break;
	case STATUSTYPE_TABLE:
		ssd_for_each_ap(os, ap, i) {
			DMEMIT("Reads: %lu Writes: %lu Delayed: %lu",
					ap->io_accesses[0], ap->io_accesses[1],
					ap->io_delayed);
		}
		break;
	}
}

static int openssd_pool_init(struct openssd *os, struct dm_target *ti)
{
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	int i, j;

	os->nr_aps_per_pool = APS_PER_POOL;
	os->serialize_ap_access = SERIALIZE_AP_ACCESS;
	os->hint_flags = 0; //DEPLOYED_HINTS;

	// Simple round-robin strategy
	atomic_set(&os->next_write_ap, -1);
	os->lookup_ltop = openssd_lookup_ltop;

	if (os->hint_flags) 
		os->map_ltop = openssd_map_swap_hint_ltop_rr;
	else
		os->map_ltop = openssd_map_ltop_rr;

	spin_lock_init(&os->hintlock);
	INIT_LIST_HEAD(&os->hintlist);

	os->nr_pools = POOL_COUNT;
	os->pools = kzalloc(sizeof(struct openssd_pool) * os->nr_pools, GFP_KERNEL);
	if (!os->pools)
		goto err_pool;

	ssd_for_each_pool(os, pool, i) {
		spin_lock_init(&pool->lock);

		INIT_LIST_HEAD(&pool->free_list);
		INIT_LIST_HEAD(&pool->used_list);
		INIT_LIST_HEAD(&pool->prio_list);

		pool->phy_addr_start = i * POOL_BLOCK_COUNT;
		pool->phy_addr_end = (i + 1) * POOL_BLOCK_COUNT - 1;

		pool->nr_free_blocks = pool->nr_blocks = pool->phy_addr_end - pool->phy_addr_start + 1;
		pool->blocks = kzalloc(sizeof(struct openssd_pool_block) * pool->nr_blocks, GFP_KERNEL);
		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			block->parent = pool;
			block->id = (i * POOL_BLOCK_COUNT) + j;

			openssd_reset_block(block);

			list_add_tail(&block->list, &pool->free_list);
			list_add_tail(&block->prio, &pool->prio_list);
		}
	}

	os->nr_aps = os->nr_aps_per_pool * os->nr_pools;;
	os->aps = kmalloc(sizeof(struct openssd_ap) * os->nr_pools * os->nr_aps, GFP_KERNEL);
	if (!os->aps)
		goto err_blocks;

	ssd_for_each_pool(os, pool, i) {
		for (j = 0; j < os->nr_aps_per_pool; j++) {
			ap = &os->aps[(i * os->nr_aps_per_pool) + j];

			spin_lock_init(&ap->lock);
			spin_lock_init(&ap->waiting_lock);
			bio_list_init(&ap->waiting_bios);
			INIT_WORK(&ap->waiting_ws, openssd_delayed_bio_submit);
			atomic_set(&ap->is_active, 0);

			ap->parent = os;
			ap->pool = pool;
			ap->cur = openssd_pool_get_block(pool); // No need to lock ap->cur.

			ap->t_read = TIMING_READ;
			ap->t_write = TIMING_WRITE;
			ap->t_erase = TIMING_ERASE;
		}
	}

	os->kbiod_wq = alloc_workqueue("kopenssd-work", WQ_MEM_RECLAIM, 0);
	if (!os->kbiod_wq) {
		DMERR("Couldn't start kopenssd-worker");
		goto err_blocks;
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

/*
 * Accepts an OpenSSD-backed block-device. The OpenSSD device should run the
 * corresponding physical firmware that exports the flash as physical without any
 * mapping and garbage collection as it will be taken care of.
 */
static int openssd_ctr(struct dm_target *ti, unsigned argc, char **argv)
{
	struct openssd *os;
	int i;

	// Which device it should map onto?
	if (argc != 1) {
		ti->error = "The target takes a single block device path as argument.";
		return -EINVAL;
	}

	os = kmalloc(sizeof(*os), GFP_KERNEL);
	if (os == NULL) {
		return -ENOMEM;
	}

	os->nr_pages = POOL_COUNT * POOL_BLOCK_COUNT * BLOCK_PAGE_COUNT * NR_HOST_PAGES_IN_FLASH_PAGE;

	os->trans_map = vmalloc(sizeof(struct openssd_addr) * os->nr_pages);
	if (!os->trans_map)
		goto err_trans_map;
	memset(os->trans_map, 0, sizeof(struct openssd_addr) * os->nr_pages);

	// initial l2p is LTOP_EMPTY
	for(i=0;i<os->nr_pages;i++) 
		os->trans_map[i].addr = LTOP_EMPTY;

	os->rev_trans_map = vmalloc(sizeof(sector_t) * os->nr_pages);
	if (!os->rev_trans_map)
		goto err_rev_trans_map;

	os->per_bio_pool = mempool_create_slab_pool(16, _per_bio_cache);
	if (!os->per_bio_pool)
		goto err_dev_lookup;

	if (dm_get_device(ti, argv[0], dm_table_get_mode(ti->table), &os->dev))
		goto err_per_bio_pool;

	if (bdev_physical_block_size(os->dev->bdev) > EXPOSED_PAGE_SIZE) {
		ti->error = "dm-openssd: Got bad sector size. Device sector size is larged then the exposed";
		goto err_per_bio_pool;
	}
	os->sector_size = EXPOSED_PAGE_SIZE;

	DMINFO("Target sector size=%d", os->sector_size);
	DMINFO("Disk logical sector size=%d", bdev_logical_block_size(os->dev->bdev));
	DMINFO("Disk physical sector size=%d", bdev_physical_block_size(os->dev->bdev));
	DMINFO("Disk flash page size=%d", FLASH_PAGE_SIZE);

	os->ti = ti;
	ti->private = os;

	/* Initialize pools. */
	openssd_pool_init(os, ti);

	// FIXME: Clean up pool init on failure.
	os->kt_openssd = kthread_run(openssd_kthread, os, "kopenssd");
	if (!os->kt_openssd)
		goto err_per_bio_pool;

	/* Relevant hinting */
	if (os->hint_flags & HINT_SWAP)
		openssd_ctr_swap_hint(os);

	DMINFO("allocated %lu physical pages (%lu KB)", os->nr_pages, os->nr_pages * os->sector_size / 1024);
	DMINFO("successful loaded");

	return 0;
err_per_bio_pool:
	mempool_destroy(os->per_bio_pool);
err_dev_lookup:
	vfree(os->rev_trans_map);
err_rev_trans_map:
	vfree(os->trans_map);
err_trans_map:
	kfree(os);
	ti->error = "dm-openssd: Cannot allocate openssd mapping context";
	return -ENOMEM;
}

static void openssd_dtr(struct dm_target *ti)
{
	struct openssd *os = (struct openssd *) ti->private;
	struct openssd_pool *pool;
	struct openssd_ap *ap;
	hint_info_t *hint_info, *next_hint_info;
	int i;

	dm_put_device(ti, os->dev);

	ssd_for_each_ap(os, ap, i) {
		while (bio_list_peek(&ap->waiting_bios))
			flush_scheduled_work();
	}

	kthread_stop(os->kt_openssd);

	ssd_for_each_pool(os, pool, i)
		kfree(pool->blocks);

	kfree(os->pools);
	kfree(os->aps);

	vfree(os->trans_map);
	vfree(os->rev_trans_map);

	destroy_workqueue(os->kbiod_wq);
	mempool_destroy(os->per_bio_pool);

	spin_lock(&os->hintlock);
	list_for_each_entry_safe(hint_info, next_hint_info, &os->hintlist, list_member) {
			list_del(&hint_info->list_member);
			DMINFO("dtr: deleted hint");
			kfree(hint_info);
	}
	spin_unlock(&os->hintlock);

	kfree(os);

	DMINFO("dm-openssd successfully unloaded");
}

static struct target_type openssd_target = {
	.name = "openssd",
	.version = {0, 0, 1},
	.module	= THIS_MODULE,
	.ctr = openssd_ctr,
	.dtr = openssd_dtr,
	.map = openssd_map,
	.ioctl = openssd_ioctl,
	.status = openssd_status,
};

static int __init dm_openssd_init(void)
{
	_per_bio_cache = kmem_cache_create("openssd_per_bio_cache",
				sizeof(struct per_bio_data), 0, 0, NULL); 
	if (!_per_bio_cache)
		return -ENOMEM;

	return dm_register_target(&openssd_target);
}

static void dm_openssd_exit(void)
{
	kmem_cache_destroy(_per_bio_cache);
	dm_unregister_target(&openssd_target);
}

module_init(dm_openssd_init);
module_exit(dm_openssd_exit);

MODULE_DESCRIPTION(DM_NAME "device-mapper openssd target");
MODULE_AUTHOR("Matias Bjørling <mb@silverwolf.dk>");
MODULE_LICENSE("GPL");

