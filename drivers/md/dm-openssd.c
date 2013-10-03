/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under GPL.
 *
 * Todo
 *
 * - Implement fetching of bad pages from flash
 *
 * Hints
 * - configurable sector size
 * - handle case of in-page bv_offset (currently hidden assumption of offset=0,
 *   and bv_len spans entire page)
 *
 * Optimization possibilities
 * - Move ap_next_write into a conconcurrency friendly data structure. Could be
 *   handled by more intelligent map_ltop function.
 * - Implement per-cpu openssd_pool_block data structure ownership. Removes need
 *   for taking lock on block next_write_id function. I.e. page allocation
 *   becomes nearly lockless, with occasionally movement of blocks on
 *   openssd_pool_block lists.
 */

#include "dm-openssd.h"

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

static inline struct per_bio_data *get_per_bio_data(struct bio *bio)
{
	return (struct per_bio_data *) bio->bi_private;
}

static struct per_bio_data *alloc_decorate_per_bio_data(struct openssd *os, struct bio *bio)
{
	struct per_bio_data *pb = mempool_alloc(os->per_bio_pool, GFP_NOIO);

	if (!pb) {
		DMERR("Couldn't allocate per_bio_data");
		return NULL;

	}

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

static void free_per_bio_data(struct openssd *os, struct per_bio_data *pb)
{
	mempool_free(pb, os->per_bio_pool);
}

static void openssd_delayed_bio_submit(struct work_struct *work)
{
	struct openssd_pool *pool = container_of(work, struct openssd_pool, waiting_ws);
	struct bio *bio;

	spin_lock(&pool->waiting_lock);
	bio = bio_list_pop(&pool->waiting_bios);
	spin_unlock(&pool->waiting_lock);

	generic_make_request(bio);
}

void openssd_update_map_generic(struct openssd *os,  sector_t l_addr,
				   sector_t p_addr, struct openssd_pool_block *p_block)
{
	struct openssd_addr *l;
	unsigned int page_offset;

	if (l_addr >= os->nr_pages || p_addr >= os->nr_pages) {
		DMERR("update_mapping: illegal address l_addr %ld p_addr %ld", l_addr, p_addr);
		return;
	}
	BUG_ON(l_addr >= os->nr_pages);
	BUG_ON(p_addr >= os->nr_pages);

	/* Primary mapping */
	DMINFO("update primary mapping l_addr %ld p_addr %ld", l_addr, p_addr);

	l = &os->trans_map[l_addr];
	if (l->block) {
		page_offset = l->addr % (NR_HOST_PAGES_IN_BLOCK);
		if (test_and_set_bit(page_offset, l->block->invalid_pages))
			WARN_ON(true);
		l->block->nr_invalid_pages++;
	}

	l->addr = p_addr;
	l->block = p_block;

	os->rev_trans_map[p_addr] = l_addr;

	/*DMINFO("update_mapping(): l_addr %lu now points to p_addr %lu", l_addr,
	 * p_addr);*/
}

sector_t openssd_alloc_addr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **victim_block, void *private)
{
	unsigned int retries;
	sector_t physical_addr = LTOP_EMPTY;

	for (retries = 0; retries < 3; retries++) {
		physical_addr = os->map_ltop(os, logical_addr, victim_block, private);

		if (physical_addr != LTOP_EMPTY)
			break;

		openssd_gc_collect(os);
	}

	return physical_addr;
}

/* requires pool->lock taken */
inline void openssd_reset_block(struct openssd_pool_block *block)
{
	unsigned int order = ffs(NR_HOST_PAGES_IN_BLOCK) - 1;

	BUG_ON(!block);

	spin_lock(&block->lock);
	if (block->data) {
		WARN_ON(!bitmap_full(block->invalid_pages, NR_HOST_PAGES_IN_BLOCK));
		bitmap_zero(block->invalid_pages, NR_HOST_PAGES_IN_BLOCK);
		__free_pages(block->data, order);
	}
	block->next_page = 0;
	block->next_offset = 0;
	block->nr_invalid_pages = 0;
	atomic_set(&block->data_size, 0);
	atomic_set(&block->data_cmnt_size, 0);
	spin_unlock(&block->lock);
}

/* use pool_[get/put]_block to administer the blocks in use for each pool.
 * Whenever a block is in used by an append point, we store it within the used_list.
 * We then move it back when its free to be used by another append point.
 *
 * The newly acclaimed block is always added to the back of user_list. As we assume
 * that the start of used list is the oldest block, and therefore higher probability
 * of invalidated pages.
 */
struct openssd_pool_block *openssd_pool_get_block(struct openssd_pool *pool)
{
	struct openssd_pool_block *block = NULL;
	struct page *data;
	unsigned int order = ffs(NR_HOST_PAGES_IN_BLOCK) - 1;

	data = alloc_pages(GFP_NOIO, order);

	if (!data)
		return NULL;

	spin_lock(&pool->lock);

	if (list_empty(&pool->free_list)) {
		spin_unlock(&pool->lock);
		__free_pages(data, order);
		return NULL;
	}

	block = list_first_entry(&pool->free_list, struct openssd_pool_block, list);
	list_move_tail(&block->list, &pool->used_list);

	pool->nr_free_blocks--;

	spin_unlock(&pool->lock);

	block->data = data;

	return block;
}


/* We assume that all valid pages have already been moved when added back to the
 * free list. We add it last to allow round-robin use of all pages. Thereby provide
 * simple (naive) wear-leveling.
 */
void openssd_pool_put_block(struct openssd_pool_block *block)
{
	struct openssd_pool *pool = block->parent;

	openssd_reset_block(block);

	spin_lock(&pool->lock);

	list_move_tail(&block->list, &pool->free_list);

	pool->nr_free_blocks++;
	spin_unlock(&pool->lock);
}

sector_t openssd_get_physical_page(struct openssd_pool_block *block)
{
	sector_t addr = LTOP_EMPTY;

	spin_lock(&block->lock);

	if (block_is_full(block))
		goto out;
	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		block->next_offset = 0;
		block->next_page++;
	}

	addr = (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) + block->next_offset;
	block->next_offset++;

out:
	spin_unlock(&block->lock);
	return addr;
}

sector_t openssd_get_physical_fast_page(struct openssd *os, struct openssd_pool_block *block)
{
	sector_t addr = LTOP_EMPTY;

	// access block next_page in protected manner
	// TODO: now that this access is protected by spinlock (to avoid race condition with
	//       openssd_get_page_id, is the atomic_XXX_return part redundant?
	spin_lock(&block->lock);
	/* Block is full */
	if (block_is_full(block)) {
		DMINFO("block is full. return -1");
		goto out;
	}

	/* If there is multiple host pages within a flash page, we add the
	 * the offset to the address, instead of requesting a new page
	 * from the physical block */
	if (block->next_offset == NR_HOST_PAGES_IN_FLASH_PAGE) {
		block->next_offset = 0;
		block->next_page++;
	}

	/* Current page is slow */
	if (!page_is_fast(block->next_page))
		goto out;

	/* Calc addr*/
	addr = (block->next_page * NR_HOST_PAGES_IN_FLASH_PAGE) + block->next_offset;
	block->next_offset++;

out:
	spin_unlock(&block->lock);
	return addr;
}

void openssd_set_ap_cur(struct openssd_ap *ap, struct openssd_pool_block *block)
{
	spin_lock(&ap->lock);
	ap->cur = block;
	DMINFO("set ap->cur with block in addr %ld", block_to_addr(block));
	spin_unlock(&ap->lock);
}

void openssd_print_total_blocks(struct openssd *os)
{
	struct openssd_pool *pool;
	unsigned int total = 0;
	int i;

	ssd_for_each_pool(os, pool, i)
		total += pool->nr_free_blocks;

	DMINFO("Total free blocks: %u", total);
}

struct openssd_addr *openssd_lookup_ltop(struct openssd *os, sector_t logical_addr)
{
	// TODO: during GC or w-r-w we may get a translation for an old page.
	//       do we care enough to enforce some serializibilty in LBA accesses?
	struct openssd_addr *addr;

	while (1) {
		addr = &os->trans_map[logical_addr];

		if (!addr->block)
			return addr;

		if (!spin_is_locked(&addr->block->gc_lock)) {
			openssd_get_block(addr->block);
			return addr;
		}

		schedule();
	}
}

static sector_t openssd_lookup_ptol(struct openssd *os, sector_t physical_addr)
{
	return os->rev_trans_map[physical_addr];
}

/* Simple round-robin Logical to physical address translation.
 *
 * Retrieve the mapping using the active append point. Then update the ap for the
 * next write to the disk.
 *
 * Returns the physical mapped address.
 */
sector_t openssd_map_ltop_rr(struct openssd *os, sector_t logical_addr, struct openssd_pool_block **ret_victim_block, void *private)
{
	struct openssd_pool_block *block;
	struct openssd_ap *ap;
	sector_t physical_addr;
	int page_id;
	int ap_id = atomic_inc_return(&os->next_write_ap) % os->nr_aps;

	ap = &os->aps[ap_id];
	block = ap->cur;
	page_id = openssd_get_physical_page(block);

	DMINFO("map_ltop_rr: page_id=%d", page_id);
	while (page_id < 0) {
		block = openssd_pool_get_block(block->parent);

		if (!block)
			return LTOP_EMPTY;

		openssd_set_ap_cur(ap, block);
		page_id = openssd_get_physical_page(block);
	}

	physical_addr = block_to_addr(block) + page_id;
	DMINFO("logical_addr=%ld new physical_addr[0]=%ld (page_id=%d, blkid=%u)", logical_addr, physical_addr, page_id, block->id);

	openssd_update_map_generic(os, logical_addr, physical_addr, block);

	(*ret_victim_block) = block;
	return physical_addr;
}

static void openssd_endio(struct bio *bio, int err)
{
	struct per_bio_data *pb;
	struct openssd *os;
	struct openssd_ap *ap;
	struct openssd_pool *pool;
	struct openssd_pool_block *block;
	struct timeval end_tv;
	unsigned long diff, dev_wait, total_wait = 0;

	pb = get_per_bio_data(bio);

	ap = pb->ap;
	os = ap->parent;
	pool = ap->pool;
	block = pb->block;
	
	DMINFO("openssd_endio: %s pb->physical_addr %ld bio->bi_sector %ld",
			(bio_data_dir(bio) == WRITE) ? "WRITE" : "READ", pb->physical_addr, bio->bi_sector);
	if (pb->physical_addr == LTOP_EMPTY) {
		DMINFO("openssd_endio: no real IO performed. goto done");
		goto done;
	}

	if (bio_data_dir(bio) == WRITE)
		dev_wait = ap->t_write;
	else {
		dev_wait = ap->t_read;
		/* remember to change accordently every usage of lookup_ltop */
		openssd_put_block(block);
	}

	openssd_delay_endio_hint(os, bio, pb, &dev_wait);

	if (dev_wait) {
		do_gettimeofday(&end_tv);
		diff = end_tv.tv_usec - pb->start_tv.tv_usec;
		if (dev_wait > diff)
			total_wait = dev_wait - diff;

		if (total_wait > 50)
			udelay(total_wait);
	}

	// Remember that the IO is first officially finished from here
	if (bio_list_peek(&pool->waiting_bios))
		queue_work(os->kbiod_wq, &pool->waiting_ws);
	else
		atomic_set(&pool->is_active, 0);

done:
	dedecorate_bio(pb, bio);

	if (bio->bi_end_io)
		bio->bi_end_io(bio, err);

	if (pb->sync)
		complete(&pb->event);

	free_per_bio_data(os, pb);
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

void openssd_submit_bio(struct openssd *os, struct openssd_pool_block *block, int rw, struct bio *bio, int sync)
{
	struct openssd_ap *ap = block_to_ap(os, block);
	struct openssd_pool *pool = ap->pool;
	struct per_bio_data *pb;

	pb = alloc_decorate_per_bio_data(os, bio);
	pb->ap = ap;
	pb->block = block;
	pb->physical_addr = bio->bi_sector;

	if (rw == WRITE)
		bio->bi_end_io = openssd_end_write_bio;
	else
		bio->bi_end_io = openssd_end_read_bio;

	/* setup timings - remember overhead. */
	do_gettimeofday(&pb->start_tv);

	if (os->serialize_pool_access && atomic_read(&pool->is_active)) {
		spin_lock(&pool->waiting_lock);
		ap->io_delayed++;
		bio_list_add(&pool->waiting_bios, bio);
		spin_unlock(&pool->waiting_lock);
	} else {
		atomic_inc(&pool->is_active);
	}

	// We allow counting to be semi-accurate as theres no locking for accounting.
	ap->io_accesses[bio_data_dir(bio)]++;

	if (sync) {
		rw |= REQ_SYNC;
		pb->sync = 1;
		init_completion(&pb->event);
		submit_bio(rw, bio);
		wait_for_completion(&pb->event);
	} else {
		pb->sync = 0;
		submit_bio(rw, bio);
	}
}

static void openssd_fill_bio_and_end(struct bio *bio)
{
	printk("no data\n");
	zero_fill_bio(bio);
	bio_endio(bio, 0);
}

void openssd_erase_block(struct openssd_pool_block *block)
{
	/* Send erase command to device. */
}

static int openssd_handle_buffered_read(struct openssd *os, struct bio *bio, struct openssd_addr *phys)
{
	int i, j, pool_idx = phys->addr / (os->nr_pages / POOL_COUNT);
	sector_t addr;
	void *src_p, *dst_p;
	struct openssd_ap *ap;
	struct bio_vec *bv;
	int idx = phys->addr % (NR_HOST_PAGES_IN_BLOCK);

	//DMINFO("chekc for buffered read");
	for (i = 0; i < os->nr_aps_per_pool; i++) {
		ap = &os->aps[(pool_idx * os->nr_aps_per_pool) + i];
		addr = block_to_addr(ap->cur) + ap->cur->next_page * NR_HOST_PAGES_IN_FLASH_PAGE;

		// if this is the first page in a the ap buffer
		//DMINFO("pool_idx=%d pool_ap=%d addr=%ld phys->addr=%ld", pool_idx, j, addr, phys->addr);
		if (addr == phys->addr) {
			printk("buffered data\n");
			bio_for_each_segment(bv, bio, j) {
				dst_p = kmap_atomic(bv->bv_page);
				src_p = kmap_atomic(&ap->cur->data[idx]);

				memcpy(dst_p, src_p, bv->bv_len);
				//DMINFO("dst_p[0]=%d", ((int*)dst_p)[0]);
				kunmap_atomic(dst_p);
				kunmap_atomic(src_p);
				break;
			}
			bio_endio(bio, 0);

			return 0;
		}
	}

	return 1;
}

int openssd_read_bio_generic(struct openssd *os, struct bio *bio)
{
	struct bio *exec_bio, *split_bio;
	struct bio_pair *bp;
	struct bio_vec *bv;
	struct openssd_addr *phys;
	sector_t log_addr;
	int i;

	if (bio_sectors(bio) > NR_PHY_IN_LOG) {
		split_bio = bio;
		bio_for_each_segment(bv, bio, i) {
			bp = bio_split(split_bio, NR_PHY_IN_LOG);

			exec_bio = &bp->bio1;
			split_bio = &bp->bio2;

			log_addr = exec_bio->bi_sector / NR_PHY_IN_LOG;
			phys = os->lookup_ltop(os, log_addr);
			DMINFO("handle_read: read log_addr %ld from phys %ld", log_addr, phys->addr);
			if (!phys->block) {
				openssd_fill_bio_and_end(bio);
				return DM_MAPIO_SUBMITTED;
			}

			exec_bio->bi_sector = phys->addr * NR_PHY_IN_LOG;

			// XXX buffered reads!

			//printk("exec_bio addr: %lu bi_sectors: %u orig_addr: %lu\n", exec_bio->bi_sector, bio_sectors(exec_bio), bio->bi_sector);
			openssd_submit_bio(os, phys->block, READ, exec_bio, 0);
		}
	} else {
		log_addr = bio->bi_sector / NR_PHY_IN_LOG;
		phys = os->lookup_ltop(os, log_addr);

		bio->bi_sector = phys->addr * NR_PHY_IN_LOG;

		if (!phys->block) {
			openssd_fill_bio_and_end(bio);
			return DM_MAPIO_SUBMITTED;
		}
		DMINFO("handle_read: read log_addr %ld from phys %ld", log_addr,
				phys->addr);
		/* When physical page contains several logical pages, we may need to
		 * read from buffer. Check if so, and if page is cached in ap, read from
		 * there */
		if (NR_HOST_PAGES_IN_FLASH_PAGE > 1) {
			//DMINFO("handle buffered read");
			if (openssd_handle_buffered_read(os, bio, phys) == 0)
				return DM_MAPIO_SUBMITTED;
		}

		//printk("phys_addr: %lu blockid %u bio addr: %lu bi_sectors: %u\n", phys->addr, phys->block->id, bio->bi_sector, bio_sectors(bio));
		openssd_submit_bio(os, phys->block, READ, bio, 0);
	}

	return DM_MAPIO_SUBMITTED;
}

int openssd_handle_buffered_write(sector_t physical_addr, struct openssd_pool_block *victim_block, struct bio_vec *bv)
{
	unsigned int idx;
	void *src_p, *dst_p;

	idx = physical_addr % (NR_HOST_PAGES_IN_FLASH_PAGE * BLOCK_PAGE_COUNT);
	src_p = kmap_atomic(bv->bv_page);
	dst_p = kmap_atomic(&victim_block->data[idx]);
	memcpy(dst_p, src_p, bv->bv_len);

	kunmap_atomic(dst_p);
	kunmap_atomic(src_p);

	return atomic_inc_return(&victim_block->data_size);
}

void openssd_submit_write(struct openssd *os, sector_t physical_addr,
				 struct openssd_pool_block* victim_block, int size)
{
	struct bio *issue_bio;
	int bv_i;

	//FIXME: can fail
	issue_bio = bio_alloc(GFP_NOIO, 2);
	issue_bio->bi_bdev = os->dev->bdev;
	issue_bio->bi_sector = ((physical_addr-1) * NR_PHY_IN_LOG);

	for (bv_i = 0; bv_i < NR_HOST_PAGES_IN_FLASH_PAGE; bv_i++) {
		unsigned int idx_to_write = size - NR_HOST_PAGES_IN_FLASH_PAGE + bv_i;
		bio_add_page(issue_bio, &victim_block->data[idx_to_write], PAGE_SIZE, 0);
	}
	openssd_submit_bio(os, victim_block, WRITE, issue_bio, 0);
}

int openssd_write_bio_generic(struct openssd *os, struct bio *bio)
{
	struct openssd_pool_block *victim_block;
	struct bio_vec *bv;
	sector_t logical_addr, physical_addr;
	int i, size;

	bio_for_each_segment(bv, bio, i) {
		if (bv->bv_len != PAGE_SIZE && bv->bv_offset != 0) {
			printk("Doesn't yet support IO sizes other than system page size. (bv_len %u bv_offset %u)", bv->bv_len, bv->bv_offset);
			return -ENOSPC;
		}

		logical_addr = (bio->bi_sector / NR_PHY_IN_LOG) + i;

		physical_addr = openssd_alloc_addr(os, logical_addr, &victim_block, NULL);
		//DMINFO("Logical: %lu Physical: %lu OS Sector addr: %ld Sectors: %u Size: %u", logical_addr, physical_addr[0], bio->bi_sector, bio_sectors(bio), bio->bi_size);

		if (physical_addr == LTOP_EMPTY) {
			DMERR("Out of physical addresses. Retry");
			return DM_MAPIO_REQUEUE;
		}

		/* Submit bio for all physical addresses*/
		DMINFO("Logical: %lu Physical: %lu OS Sector addr: %ld Sectors: %u Size: %u", logical_addr, physical_addr, bio->bi_sector, bio_sectors(bio), bio->bi_size);

		size = openssd_handle_buffered_write(physical_addr, victim_block, bv);
		if (size % NR_HOST_PAGES_IN_FLASH_PAGE == 0)
			openssd_submit_write(os, physical_addr, victim_block, size);
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
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
		break;
	}

	return openssd_ioctl_hint(os, cmd, arg);
}

static int openssd_map(struct dm_target *ti, struct bio *bio)
{
	struct openssd *os = ti->private;
	int ret;
	bio->bi_bdev = os->dev->bdev;

	//DMINFO("openssd_map: %s log_addr %ld, call handler", (bio_data_dir(bio) == WRITE)?"WRITE":"READ", bio->bi_sector/8);
	if (bio_data_dir(bio) == WRITE)
		ret = os->write_bio(os, bio);
	else
		ret = os->read_bio(os, bio);
	DMINFO("openssd_map: %s log_addr %ld, handler done!!", (bio_data_dir(bio) ==
				WRITE) ? "WRITE" : "READ", bio->bi_sector/8);
	return ret;
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

	spin_lock_init(&os->gc_lock);

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
		spin_lock_init(&pool->waiting_lock);
		bio_list_init(&pool->waiting_bios);
		INIT_WORK(&pool->waiting_ws, openssd_delayed_bio_submit);
		atomic_set(&pool->is_active, 0);

		if (!pool->blocks)
			goto err_blocks;

		pool_for_each_block(pool, block, j) {
			spin_lock_init(&block->lock);
			spin_lock_init(&block->gc_lock);

			if (percpu_ref_init(&block->ref_count, openssd_block_release))
				goto err_blocks;

			block->parent = pool;
			block->id = (i * POOL_BLOCK_COUNT) + j;

			openssd_reset_block(block);

			list_add_tail(&block->list, &pool->free_list);
			list_add_tail(&block->prio, &pool->prio_list);
		}
	}

	os->nr_aps = os->nr_aps_per_pool * os->nr_pools;
	os->aps = kmalloc(sizeof(struct openssd_ap) * os->nr_pools * os->nr_aps, GFP_KERNEL);
	if (!os->aps)
		goto err_blocks;

	ssd_for_each_pool(os, pool, i) {
		for (j = 0; j < os->nr_aps_per_pool; j++) {
			ap = &os->aps[(i * os->nr_aps_per_pool) + j];

			spin_lock_init(&ap->lock);
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
		pool_for_each_block(pool, block, j) {
			percpu_ref_cancel_init(&block->ref_count);
		}
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

	os = kzalloc(sizeof(*os), GFP_KERNEL);
	if (os == NULL)
		return -ENOMEM;

	os->nr_pages = POOL_COUNT * POOL_BLOCK_COUNT * NR_HOST_PAGES_IN_BLOCK;

	os->trans_map = vmalloc(sizeof(struct openssd_addr) * os->nr_pages);
	if (!os->trans_map)
		goto err_trans_map;
	memset(os->trans_map, 0, sizeof(struct openssd_addr) * os->nr_pages);

	// initial l2p is LTOP_EMPTY
	for (i = 0; i < os->nr_pages; i++)
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
	os->nr_aps_per_pool = APS_PER_POOL;
	os->serialize_pool_access = SERIALIZE_POOL_ACCESS;

	// Simple round-robin strategy
	atomic_set(&os->next_write_ap, -1);

	os->lookup_ltop = openssd_lookup_ltop;
	os->lookup_ptol = openssd_lookup_ptol;
	os->map_ltop = openssd_map_ltop_rr;
	os->write_bio = openssd_write_bio_generic;
	os->read_bio = openssd_read_bio_generic;

	if (openssd_alloc_hint(os))
		goto err_per_bio_pool;

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

	if (openssd_init_hint(os))
		goto err_per_bio_pool; // possible mem leak from pool_init.

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
	struct openssd_pool_block *block;
	int i, j;

	dm_put_device(ti, os->dev);

	ssd_for_each_pool(os, pool, i) {
		while (bio_list_peek(&pool->waiting_bios))
			flush_scheduled_work();
	}

	kthread_stop(os->kt_openssd);

	ssd_for_each_pool(os, pool, i) {
		pool_for_each_block(pool, block, j)
			percpu_ref_kill(&block->ref_count);
		kfree(pool->blocks);
	}

	kfree(os->pools);
	kfree(os->aps);

	vfree(os->trans_map);
	vfree(os->rev_trans_map);

	destroy_workqueue(os->kbiod_wq);
	mempool_destroy(os->per_bio_pool);

	openssd_free_hint(os);

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
