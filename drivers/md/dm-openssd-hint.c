#include "dm-openssd.h"
#include "dm-openssd-hint.h"

/* Configuration of hints that are deployed within the openssd instance */
#define DEPLOYED_HINTS /*(HINT_NONE) */ (HINT_LATENCY | HINT_IOCTL) /* (HINT_SWAP | HINT_IOCTL) */

#define VERIFY_HINT(HINT_FLAGS, HINT_TYPE)  (((HINT_FLAGS) & HINT_TYPE) && (DEPLOYED_HINTS & HINT_TYPE))
#define IS_HINT_DEPLOYED(HINT_FLAGS) (VERIFY_HINT(HINT_FLAGS, HINT_SWAP) || VERIFY_HINT(HINT_FLAGS, HINT_LATENCY))

void openssd_delay_endio_hint(struct openssd *os, struct bio *bio, struct per_bio_data *pb, unsigned long *delay)
{
	struct openssd_hint *hint = os->hint_private;
	int page_id;

	if ((hint->hint_flags & HINT_SWAP) && bio_data_dir(bio) == WRITE) {
		page_id = (pb->physical_addr / NR_HOST_PAGES_IN_FLASH_PAGE) % BLOCK_PAGE_COUNT;

		// TODO: consider dev_wait to be part of per_bio_data?
		if (page_is_fast(page_id))
			(*delay) = TIMING_WRITE_FAST;
		else
			(*delay) = TIMING_WRITE_SLOW;
	}
}

void *openssd_begin_gc_hint(sector_t l_addr, sector_t p_addr, struct
		nvm_block *block)
{
	struct openssd_hint_map_private *private =
		kzalloc(sizeof(struct openssd_hint_map_private), GFP_NOIO);

	private->old_p_addr = p_addr;

	return private;
}

void openssd_end_gc_hint(void *private)
{
	kfree(private);
}

// iterate hints list, and check if lba of current req is covered by some hint
hint_info_t* openssd_find_hint(struct openssd *os, sector_t logical_addr, bool is_write)
{
	struct openssd_hint *hint = os->hint_private;
	hint_info_t *hint_info;
	struct list_head *node;

	//DMINFO("find hint for lba %ld is_write %d", logical_addr, is_write);
	spin_lock(&hint->hintlock);
	/*see if hint is already in list*/
	list_for_each(node, &hint->hintlist) {
		hint_info = list_entry(node, hint_info_t, list_member);
		//DMINFO("hint start_lba=%d count=%d", hint_info->hint.start_lba, hint_info->hint.count);
		//continue;
		/* verify lba covered by hint*/
		if (is_hint_relevant(logical_addr, hint_info, is_write, DEPLOYED_HINTS)) {
			DMINFO("found hint for lba %ld",logical_addr);
			hint_info->processed++;
			spin_unlock(&hint->hintlock);
			return hint_info;
		}
	}
	spin_unlock(&hint->hintlock);
	DMINFO("no hint found for %s lba %ld", (is_write)?"WRITE":"READ",logical_addr);

	return NULL;
}

fclass file_classify(struct bio_vec* bvec)
{
	fclass fc = FC_UNKNOWN;
	char *sec_in_mem;
	char byte[4];

	if (!bvec || !bvec->bv_page) {
		DMINFO("can't kmap empty bvec->bv_page. kmap failed");
		return fc;
	}

	byte[0] = 0x66;
	byte[1] = 0x74;
	byte[2] = 0x79;
	byte[3] = 0x70;

	sec_in_mem = kmap_atomic((bvec->bv_page) + bvec->bv_offset);

	if (!sec_in_mem) {
		DMERR("bvec->bv_page kmap failed");
		return fc;
	}

	if (!memcmp(sec_in_mem+4, byte,4)) {
		//hint_log("VIDEO classified");
		DMINFO("VIDEO classified");
		fc = FC_VIDEO_SLOW;
	}

	kunmap_atomic(sec_in_mem);
	return fc;
}

/* no real sending for now, in prototype just put it directly in FTL's hints list
   and update ino_hint map when necessary*/
static int openssd_send_hint(struct openssd *os, hint_data_t *hint_data)
{
	struct openssd_hint *hint = os->hint_private;
	int i;
	hint_info_t* hint_info;

	DMINFO("first %s hint count=%d lba=%d fc=%d",
	       CAST_TO_PAYLOAD(hint_data)->is_write ? "WRITE" : "READ",
	       CAST_TO_PAYLOAD(hint_data)->count,
	       INO_HINT_FROM_DATA(hint_data, 0).start_lba,
	       INO_HINT_FROM_DATA(hint_data, 0).fc);

	// assert hint support
	if (!hint->hint_flags)
		goto send_done;

	if(!IS_HINT_DEPLOYED(hint->hint_flags)){
		DMINFO("got hint of type %d unsupported ", hint->hint_flags);
		goto send_done;
	}

	// assert relevant hint support
	if (CAST_TO_PAYLOAD(hint_data)->hint_flags & HINT_SWAP && !(hint->hint_flags & HINT_SWAP)) {
		DMINFO("hint of types %x not supported (1st entry ino %lu lba %u count %u)",
		       CAST_TO_PAYLOAD(hint_data)->hint_flags,
		       INO_HINT_FROM_DATA(hint_data, 0).ino,
		       INO_HINT_FROM_DATA(hint_data, 0).start_lba,
		       INO_HINT_FROM_DATA(hint_data, 0).count);
		goto send_done;
	}

	// insert to hints list
	for(i = 0; i < CAST_TO_PAYLOAD(hint_data)->count; i++) {
		// handle file type  for
		// 1) identified latency writes
		// 2) TODO
		if (hint->hint_flags & HINT_LATENCY && INO_HINT_FROM_DATA(hint_data, i).fc != FC_EMPTY) {
			DMINFO("ino %lu got new fc %d", INO_HINT_FROM_DATA(hint_data, i).ino,
			       INO_HINT_FROM_DATA(hint_data, i).fc);
			hint->ino_hints[INO_HINT_FROM_DATA(hint_data, i).ino] = INO_HINT_FROM_DATA(hint_data, 0).fc;
		}

		// insert to hints list
		hint_info = kmalloc(sizeof(hint_info_t), GFP_KERNEL);
		if (!hint_info) {
			DMERR("can't allocate hint info");
			return -ENOMEM;
		}
		memcpy(&hint_info->hint, &INO_HINT_FROM_DATA(hint_data, i), sizeof(ino_hint_t));
		hint_info->processed  = 0;
		hint_info->is_write   = CAST_TO_PAYLOAD(hint_data)->is_write;
		hint_info->hint_flags = CAST_TO_PAYLOAD(hint_data)->hint_flags;

		DMINFO("about to add hint_info to list. %s %s",
		       (CAST_TO_PAYLOAD(hint_data)->hint_flags & HINT_SWAP) ? "SWAP" :
		       (CAST_TO_PAYLOAD(hint_data)->hint_flags & HINT_LATENCY)?"LATENCY":"REGULAR",
		       (CAST_TO_PAYLOAD(hint_data)->is_write) ? "WRITE" : "READ");

		spin_lock(&hint->hintlock);
		list_add_tail(&hint_info->list_member, &hint->hintlist);
		spin_unlock(&hint->hintlock);
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
void openssd_bio_hint(struct openssd *os, struct bio *bio)
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
			if (PageSwapCache(bv_page)) {
				DMINFO("swap bio");
				// TODO - not tested
				CAST_TO_PAYLOAD(hint_data)->hint_flags |= HINT_SWAP;

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

				if (!host->i_sb || !host->i_sb->s_type || !host->i_sb->s_type->name) {
					DMINFO("not related to file system");
					bio_len += bvec[0].bv_len;
					continue;
				}

				if (!ino) {
					DMINFO("not inode related");
					bio_len += bvec[0].bv_len;
					continue;
				}
				//if (bvec[0].bv_offset)
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
				if (prev_ino == ino) {
					hint_idx = CAST_TO_PAYLOAD(hint_data)->count - 1;
					if (INO_HINT_FROM_DATA(hint_data, hint_idx).ino != ino) {
						DMERR("updating hint of wrong ino (ino=%u expected=%lu)", ino,
						      INO_HINT_FROM_DATA(hint_data, hint_idx).ino);
						bio_len += bvec[0].bv_len;
						continue;
					}

					INO_HINT_FROM_DATA(hint_data, hint_idx).count +=
					        bvec[0].bv_len / sector_size;
					DMINFO("increase count for hint %u. new count=%u",
					       hint_idx, INO_HINT_FROM_DATA(hint_data, hint_idx).count);
					bio_len+= bvec[0].bv_len;
					continue;
				}

				if (HINT_DATA_MAX_INOS == CAST_TO_PAYLOAD(hint_data)->count) {
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
	if (CAST_TO_PAYLOAD(hint_data)->count == 0) {
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

static int openssd_read_bio_hint(struct openssd *os, struct bio *bio)
{
	return openssd_read_bio_generic(os, bio);
}

static void openssd_trim_map_shadow(struct openssd *os, sector_t l_addr, sector_t p_addr);

static int openssd_write_bio_hint(struct openssd *os, struct bio *bio)
{
	struct openssd_hint *hint = os->hint_private;
	struct nvm_block *victim_block;
	struct bio_vec *bv;
	sector_t logical_addr, physical_addr;
	int i, j, size;
	unsigned int numCopies = 1;
	struct openssd_hint_map_private map_alloc_data;

	map_alloc_data.prev_ap = NULL;
	map_alloc_data.old_p_addr = LTOP_EMPTY;
	map_alloc_data.flags = MAP_PRIMARY;

	/* do hint */
	openssd_bio_hint(os, bio);

	bio_for_each_segment(bv, bio, i) {
		if (bv->bv_len != PAGE_SIZE && bv->bv_offset != 0) {
			printk("Doesn't yet support IO sizes other than system page size. (bv_len %u bv_offset %u)", bv->bv_len, bv->bv_offset);
			return -ENOSPC;
		}

		logical_addr = (bio->bi_sector / NR_PHY_IN_LOG) + i;

		map_alloc_data.hint_info = openssd_find_hint(os, logical_addr, 1);

		if (map_alloc_data.hint_info && map_alloc_data.hint_info->hint_flags & HINT_LATENCY)
			numCopies = 2;

		/* Submit bio for all physical addresses*/
		DMDEBUG("numCopies=%d", numCopies);
		for(j = 0; j < numCopies; j++) {

			if (j == 1)
				map_alloc_data.flags = MAP_SHADOW;

			physical_addr = openssd_alloc_addr_retries(os, logical_addr, &victim_block, &map_alloc_data);

			if (physical_addr == LTOP_EMPTY) {
				DMERR("Out of physical addresses. Retry");
				return DM_MAPIO_REQUEUE;
			}

			DMINFO("Logical: %lu Physical: %lu OS Sector addr: %ld Sectors: %u Size: %u", logical_addr, physical_addr, bio->bi_sector, bio_sectors(bio), bio->bi_size);

			size = openssd_handle_buffered_write(physical_addr, victim_block, bv);
			if (size % NR_HOST_PAGES_IN_FLASH_PAGE == 0)
				openssd_submit_write(os, physical_addr, victim_block, size);
		}

		/* trim old shadow when necessary (currently no support for multiple hint types at once) */
		if(DEPLOYED_HINTS & HINT_LATENCY && numCopies==1)
			openssd_trim_map_shadow(os, logical_addr, physical_addr);
	}

	/* Processed entire hint */
	if (map_alloc_data.hint_info) {
		spin_lock(&hint->hintlock);
		if (map_alloc_data.hint_info->processed == map_alloc_data.hint_info->hint.count) {
			//DMINFO("delete latency hint");
			list_del(&map_alloc_data.hint_info->list_member);
			kfree(map_alloc_data.hint_info);
		}
		spin_unlock(&hint->hintlock);
	}

	bio_endio(bio, 0);
	return DM_MAPIO_SUBMITTED;
}

// do any shadow address updating required (real, none, or trim of old one)
static void openssd_update_map_shadow(struct openssd *os,
			sector_t l_addr, sector_t p_addr,
			struct nvm_block *p_block, unsigned long flags)
{
	struct openssd_hint *hint = os->hint_private;
	struct nvm_addr *l;
	unsigned int page_offset;

	DMDEBUG("flags=%lu", flags);
	/* Secondary mapping. update shadow */
	if(flags & MAP_SHADOW) {
		DMDEBUG("update shadow mapping l_addr %ld p_addr %ld", l_addr, p_addr);

		l = &hint->shadow_map[l_addr];
		if (l->block) {
			page_offset = l->addr % (NR_HOST_PAGES_IN_BLOCK);
			if(test_and_set_bit(page_offset, l->block->invalid_pages))
				WARN_ON(true);
			l->block->nr_invalid_pages++;
		}

		l->addr = p_addr;
		l->block = p_block;

		os->rev_trans_map[p_addr] = l_addr;

		return;
	}
	else if (flags & MAP_PRIMARY) {
		DMERR("should update primary only");
		return;
	}

	/* Remove old shadow mapping from shadow map */
	DMDEBUG("init shadow");
	l = &hint->shadow_map[l_addr];
	l->addr = 0;
	l->block = NULL;
}

static unsigned long openssd_get_mapping_flag(struct openssd *os, sector_t logical_addr, sector_t old_p_addr);

/* Latency-proned Logical to physical address translation.
 *
 * If latency hinted write, write data to two locations, and save extra mapping
 * If non-hinted write - resort to normal allocation
 * if GC write - no hint, but we use regular map_ltop() with GC addr
 */
static sector_t openssd_map_latency_hint_ltop_rr(struct openssd *os, sector_t logical_addr, struct nvm_block **ret_victim_block, void *private)
{
	struct openssd_hint_map_private *map_alloc_data = private;
	struct nvm_ap *ap;
	sector_t physical_addr;

	/* If there is no hint, or this is a reclaimed ltop mapping,
	 * use regular (single-page) map_ltop. handle both primary and shadow cases*/
	DMINFO("map_alloc_data %p", map_alloc_data);
	if (map_alloc_data->old_p_addr != LTOP_EMPTY || !map_alloc_data->hint_info) {
		DMDEBUG("reclaimed or regular allocation");
		// dont pass map_alloc_data for primary
		map_alloc_data->flags = openssd_get_mapping_flag(os, logical_addr, map_alloc_data->old_p_addr);
		physical_addr = openssd_alloc_map_ltop_rr(os, logical_addr, ret_victim_block,
						    (map_alloc_data->flags & (MAP_SHADOW))?map_alloc_data:(void*)NULL);

		// will do nothing if primary
		DMDEBUG("update_map_shaddow");
		openssd_update_map_shadow(os, logical_addr, physical_addr,
					(*ret_victim_block), map_alloc_data->flags);

		return physical_addr;
	}
	DMDEBUG("latency_ltop: allocate page");

	if (map_alloc_data->flags & MAP_PRIMARY) {
		physical_addr = openssd_alloc_map_ltop_rr(os, logical_addr, ret_victim_block, NULL);
		map_alloc_data->prev_ap = block_to_ap(os, (*ret_victim_block));
		return physical_addr;
	}

	do {
		ap = get_next_ap(os);
	} while (map_alloc_data->prev_ap == ap);

	physical_addr = openssd_alloc_addr_from_ap(ap, ret_victim_block);
	openssd_update_map_shadow(os, logical_addr, physical_addr, (*ret_victim_block), map_alloc_data->flags);

	DMDEBUG("retrieved addrs of shadow page");

	return physical_addr;
}

/* Swap-proned Logical to physical address translation.
 *
 * If swap write, use simple fast page allocation - find some append point whose next page is fast.
 * Then update the ap for the next write to the disk.
 * If no reelvant ap found, or non-swap write - resort to normal allocation
 */
static sector_t openssd_map_swap_hint_ltop_rr(struct openssd *os, sector_t logical_addr, struct nvm_block **ret_victim_block, void *private)
{
	struct openssd_hint_map_private *map_alloc_data = private;
	sector_t physical_addr;

	/* Check if there is a hint for relevant sector
	 * if not, resort to openssd_map_ltop_rr */
	if(map_alloc_data){
		if (map_alloc_data->old_p_addr == LTOP_EMPTY && !map_alloc_data->hint_info) {
			DMDEBUG("swap_map: non-GC non-hinted write");
			return openssd_alloc_map_ltop_rr(os, logical_addr, ret_victim_block, NULL);
		}

		/* GC write of a slow page */
		if (map_alloc_data->old_p_addr != LTOP_EMPTY && !page_is_fast(physical_to_slot(map_alloc_data->old_p_addr))) {
			DMDEBUG("swap_map: GC write of a SLOW page (old_p_addr %ld block offset %d)", map_alloc_data->old_p_addr, physical_to_slot(map_alloc_data->old_p_addr));
			return openssd_alloc_map_ltop_rr(os, logical_addr, ret_victim_block, NULL);
		}

		/*if (map_alloc_data->old_p_addr != LTOP_EMPTY)
			DMDEBUG("swap_map: GC write of a FAST page (old_p_addr %ld block offset %d)", map_alloc_data->old_p_addr, physical_to_slot(map_alloc_data->old_p_addr));*/
	}

	/* hinted write, or GC of FAST page*/
	physical_addr = openssd_alloc_phys_fastest_addr(os, ret_victim_block);

	/* no FAST page found. restort to regular allocation */
	if(physical_addr == LTOP_EMPTY){
		return openssd_alloc_map_ltop_rr(os, logical_addr, ret_victim_block, NULL);
	}

	//DMINFO("swap_rr: logical_addr=%ld physical_addr[0]=%ld (page_id=%d, blkid=%u)", logical_addr, physical_addr[0], page_id, block->id);
	//DMINFO("swap_rr: got physical_addr %d *ret_victim_block %p", physical_addr, *ret_victim_block);
	openssd_update_map_generic(os, logical_addr, physical_addr, (*ret_victim_block));

	DMDEBUG("write lba %ld to FAST page %ld (*ret_victim_block=%p)", logical_addr, physical_addr, (*ret_victim_block));
	return physical_addr;
}

// TODO: actually finding a non-busy pool is not enough. read should be moved up the request queue.
//	 however, no queue maipulation impl. yet...
static struct nvm_addr *openssd_latency_lookup_ltop(struct openssd *os, sector_t logical_addr) {
	struct openssd_hint *hint = os->hint_private;
	// TODO: during GC or w-r-w we may get a translation for an old page.
	//       do we care enough to enforce some serializibilty in LBA accesses?
	int pool_idx;
	//DMINFO("latency_lookup_ltop: logical_addr=%ld", logical_addr);

	// shadow is empty
	if (hint->shadow_map[logical_addr].addr == LTOP_EMPTY) {
		DMINFO("no shadow. read primary");
		return openssd_lookup_ltop(os, logical_addr);
	}

	// check if primary is busy
	pool_idx = os->trans_map[logical_addr].addr / (os->nr_pages / POOL_COUNT);
	if (atomic_read(&os->pools[pool_idx].is_active)) {
		DMINFO("primary busy. read shadow");
		return &hint->shadow_map[logical_addr];
	}

	// primary not busy
	DMINFO("primary not busy");
	return openssd_lookup_ltop(os, logical_addr);
}

static unsigned long openssd_get_mapping_flag(struct openssd *os, sector_t logical_addr, sector_t old_p_addr)
{
	struct openssd_hint *hint = os->hint_private;
	unsigned long flag = MAP_PRIMARY;

	//DMINFO("os->trans_map[%ld].addr %ld hint->shadow_map[%ld].addr", logical_addr, os->trans_map[logical_addr].addr, logical_addr, hint->shadow_map[logical_addr].addr);
	if(old_p_addr != LTOP_EMPTY) {
		flag = MAP_SINGLE;
		if(os->trans_map[logical_addr].addr == old_p_addr)
			flag |= MAP_PRIMARY;
		else if(hint->shadow_map[logical_addr].addr == old_p_addr)
			flag |= MAP_SHADOW;
		else {
			DMERR("Reclaiming a physical page %ld not mapped by any logical addr", old_p_addr);
			WARN_ON(true);
		}
	}

	return flag;
}


// if we ever support trim, this may be unified with some generic function
static void openssd_trim_map_shadow(struct openssd *os, sector_t l_addr, sector_t p_addr)
{
	struct openssd_hint *hint = os->hint_private;
	struct nvm_addr *l;
	unsigned int page_offset;

	DMINFO("trim old shaddow");
	l = &hint->shadow_map[l_addr];
	if (l->block) {
		page_offset = l->addr % (NR_HOST_PAGES_IN_BLOCK);
		if(test_and_set_bit(page_offset, l->block->invalid_pages))
			WARN_ON(true);
		l->block->nr_invalid_pages++;
	}

	l->addr = 0;
	l->block = 0;

	os->rev_trans_map[p_addr] = l_addr;
}

int openssd_ioctl_user_hint_cmd(struct openssd *os, unsigned long arg)
{
	hint_data_t __user *uhint = (hint_data_t __user *)arg;
	hint_data_t* hint_data;
	DMINFO("send user hint");

	/* allocate hint_data */
	hint_data = kmalloc(sizeof(hint_data_t), GFP_KERNEL);
	if (!hint_data) {
		DMERR("hint_data_t kmalloc failed");
		return -ENOMEM;
	}

	// copy hint data from user space
	if (copy_from_user(hint_data, uhint, sizeof(hint_data_t)))
		return -EFAULT;

	// send hint to device
	return openssd_send_hint(os, hint_data);
}

int openssd_ioctl_kernel_hint_cmd(struct openssd *os, unsigned long arg)
{
	hint_data_t *hint = (hint_data_t *)arg;
	// send hint to device
	// TODO: do we need to free khint here? or is it freed by block layer?
	return openssd_send_hint(os, hint);
}

int openssd_ioctl_hint(struct openssd *os, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case OPENSSD_IOCTL_SUBMIT_HINT:
		return openssd_ioctl_user_hint_cmd(os, arg);
	case OPENSSD_IOCTL_KERNEL_HINT:
		return openssd_ioctl_kernel_hint_cmd(os, arg);
	default:
		return 0;
		//return __blkdev_driver_ioctl(os->dev->bdev, os->dev->mode, cmd, arg);
	}

	return 0;
}

int openssd_init_hint(struct openssd *os)
{
	return 0;
}

int openssd_alloc_hint(struct openssd *os)
{
	struct openssd_hint *hint;
	int i;

	hint = kmalloc(sizeof(struct openssd_hint), GFP_KERNEL);
	if (!hint)
		return -ENOMEM;

	hint->hint_flags = DEPLOYED_HINTS;

	// initla shadow maps are empty
	hint->shadow_map = vmalloc(sizeof(struct nvm_addr) * os->nr_pages);
	if (!hint->shadow_map)
		goto err_shadow_map;
	memset(hint->shadow_map, 0, sizeof(struct nvm_addr) * os->nr_pages);

	// initial shadow l2p is LTOP_EMPTY
	for(i = 0; i < os->nr_pages; i++)
		hint->shadow_map[i].addr = LTOP_EMPTY;

	spin_lock_init(&hint->hintlock);
	INIT_LIST_HEAD(&hint->hintlist);

	hint->ino_hints = kzalloc(HINT_MAX_INOS, GFP_KERNEL); // ino ~> hinted file type
	if (!hint->ino_hints)
		goto err_hints;

	if (hint->hint_flags & HINT_SWAP) {
		DMINFO("Swap hint support");
		os->map_ltop = openssd_map_swap_hint_ltop_rr;
		os->write_bio = openssd_write_bio_hint;
		os->read_bio = openssd_read_bio_hint;
		os->begin_gc_private = openssd_begin_gc_hint;
		os->end_gc_private = openssd_end_gc_hint;
	} else if (hint->hint_flags & HINT_LATENCY) {
		DMINFO("Latency hint support");
		os->map_ltop = openssd_map_latency_hint_ltop_rr;
		os->lookup_ltop = openssd_latency_lookup_ltop;
		os->write_bio = openssd_write_bio_hint;
		os->read_bio = openssd_read_bio_hint;
		os->begin_gc_private = openssd_begin_gc_hint;
		os->end_gc_private = openssd_end_gc_hint;
	}

	os->hint_private = hint;

	return 0;
err_hints:
	vfree(hint->shadow_map);
err_shadow_map:
	kfree(hint);
	return -ENOMEM;
}

void openssd_free_hint(struct openssd *os)
{
	struct openssd_hint *hint = os->hint_private;
	hint_info_t *hint_info, *next_hint_info;

	spin_lock(&hint->hintlock);
	list_for_each_entry_safe(hint_info, next_hint_info, &hint->hintlist, list_member) {
		list_del(&hint_info->list_member);
		DMINFO("dtr: deleted hint");
		kfree(hint_info);
	}
	spin_unlock(&hint->hintlock);

	kfree(hint->ino_hints);
	vfree(hint->shadow_map);

	kfree(os->hint_private);
}

void openssd_exit_hint(struct openssd *os)
{
	// release everything else needed
}
