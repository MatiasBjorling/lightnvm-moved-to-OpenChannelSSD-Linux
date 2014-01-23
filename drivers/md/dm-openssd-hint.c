#include "dm-openssd.h"
#include "dm-openssd-hint.h"

static struct kmem_cache *_map_alloc_cache;

static inline unsigned long diff_tv(struct timeval *curr_tv, struct timeval *ap_tv)
{
	if (curr_tv->tv_sec == ap_tv->tv_sec)
		return curr_tv->tv_usec - ap_tv->tv_usec;

	return (curr_tv->tv_sec - ap_tv->tv_sec -1) * 1000000
				+ (1000000-ap_tv->tv_usec) + curr_tv->tv_usec;
}

void nvm_delay_endio_hint(struct nvmd *nvmd, struct bio *bio,
                              struct per_bio_data *pb, unsigned long *delay)
{
	int page_id;

	if (!(nvmd->config.flags & NVM_OPT_ENGINE_SWAP))
		return;

	if (bio_data_dir(bio) != WRITE)
		return;

	page_id = (pb->addr->addr / NR_HOST_PAGES_IN_FLASH_PAGE)
	          % nvmd->nr_pages_per_blk;

	/* different timings, roughly based on "Harey Tortoise" paper
	 * TODO: ratio is actually 4.8 on average
	 * TODO: consider dev_wait to be part of per_bio_data? */
	if (page_is_fast(nvmd, page_id))
		(*delay) = nvmd->config.t_write / 2;
	else
		(*delay) = nvmd->config.t_write * 2;
}

void nvm_hint_defer_bio(struct nvmd *nvmd, struct bio *bio)
{
	/* FIXME: only defer primary, discard secondary to minimize inconsistency*/
	return nvm_defer_bio(nvmd, bio);
}

static unsigned long nvm_get_mapping_flag(struct nvmd *nvmd, sector_t logical_addr, sector_t old_p_addr);

struct nvm_hint_map_private *alloc_latency_hint_data(struct nvmd *nvmd, unsigned long flags, sector_t old_p_addr, struct hint_info *info, struct page *page);

void *nvm_begin_gc_hint(struct nvmd *nvmd, sector_t l_addr, sector_t p_addr, struct
                            nvm_block *block)
{
	struct nvm_hint_map_private *map_alloc_data;
	int flags = nvm_get_mapping_flag(nvmd, l_addr, p_addr);

	/* no need for hint private data for primary mapping*/
	if(flags == MAP_PRIMARY)
		return NULL;

	map_alloc_data = alloc_latency_hint_data(nvmd, flags, p_addr, NULL, NULL);
	DMERR("begin_gc_hint: l_addr %ld p_addr %ld is shadow", l_addr, p_addr);
	if (!map_alloc_data){
		DMERR("Error: alloc nvm_begin_gc_hint failed");
	}

	return map_alloc_data;
}

void nvm_end_gc_hint(struct nvmd *nvmd, void *private)
{
	struct nvm_hint *hint;
	if (private) {
		hint = nvmd->hint_private;
		mempool_free(private, hint->map_alloc_pool);
	}
}

// iterate hints list, and check if lba of current req is covered by some hint
struct hint_info *nvm_find_hint(struct nvmd *nvmd, sector_t l_addr, bool is_write)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct hint_info *info = NULL;
	struct list_head *node;

	//DMERR("find hint for lba %ld is_write %d", l_addr, is_write);
	spin_lock(&hint->lock);
	/*see if hint is already in list*/
	list_for_each(node, &hint->hints) {
		info = list_entry(node, struct hint_info, list_member);
		if (is_hint_relevant(l_addr, info, is_write, nvmd->config.flags)) {
			DMDEBUG("found hint for lba %ld (ino %ld)",
						l_addr, info->hint.ino);
			info->processed++;
			goto end_hint;
		}
	}
	//DMERR("no hint found for %s lba %ld", (is_write) ? "WRITE" : "READ", l_addr);
end_hint:
	spin_unlock(&hint->lock);
	return info;
}

enum fclass file_classify(struct bio_vec *bvec)
{
	enum fclass fc = FC_UNKNOWN;
	char *sec_in_mem;
	char byte[4];

	if (!bvec || !bvec->bv_page) {
		DMINFO("can't kmap empty bvec->bv_page. kmap failed");
		return fc;
	}

	/* identifies a video file
	 * FIXME: MB: Aviad, can you elaborate on what file format, etc.? 
	 */
	byte[0] = 0x66;
	byte[1] = 0x74;
	byte[2] = 0x79;
	byte[3] = 0x70;

	sec_in_mem = kmap_atomic((bvec->bv_page) + bvec->bv_offset);

	if (!sec_in_mem) {
		DMERR("bvec->bv_page kmap failed");
		return fc;
	}

	if (!memcmp(sec_in_mem + 4, byte, 4)) {
		//hint_log("VIDEO classified");
		DMINFO("VIDEO classified");
		fc = FC_VIDEO_SLOW;
	}

	if (sec_in_mem[0] == 0xfffffffe && sec_in_mem[1] == 0xfffffffe &&
				sec_in_mem[2] == 0x07 && sec_in_mem[3] == 0x01) {
		DMINFO("identified DB_INDEX file");
		fc = FC_DB_INDEX;
	}

	kunmap_atomic(sec_in_mem);
	return fc;
}

int nvm_is_fc_latency(enum fclass fc)
{
	return (fc == FC_DB_INDEX);
}

int nvm_is_fc_packable(enum fclass fc)
{
	return (fc == FC_VIDEO_SLOW);
}

/* no real sending for now, in prototype just put it directly in FTL's hints list
   and update ino_hint map when necessary*/
static int nvm_send_hint(struct nvmd *nvmd, struct hint_payload *d)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct hint_info *info;

	if (!(nvmd->config.flags &
		(NVM_OPT_ENGINE_LATENCY |
		NVM_OPT_ENGINE_SWAP |
		NVM_OPT_ENGINE_PACK))) {
		DMERR("got unsupported hint");
		goto send_done;
	}

	/*DMERR("first %s hint count=%d lba=%d fc=%d",
		d->is_write ? "WRITE" : "READ",
		d->sectors_count,
		d->ino.start_lba,
		d->ino.fc);*/

	// assert relevant hint support
	/* FIXME: replace with shift of correct flags in nvmd->config.flags */
	if ((d->flags & NVM_OPT_ENGINE_SWAP && !(nvm_engine(nvmd, NVM_OPT_ENGINE_SWAP))) ||
	    (d->flags & NVM_OPT_ENGINE_LATENCY && !(nvm_engine(nvmd, NVM_OPT_ENGINE_LATENCY))) ||
	    (d->flags & NVM_OPT_ENGINE_PACK && !(nvm_engine(nvmd,
							    NVM_OPT_ENGINE_PACK)))) {
		DMERR("hint of types %x not supported (1st entry ino %lu lba %u count %u)",
			d->flags,
			d->ino.ino,
			d->ino.start_lba,
			d->ino.count);
		goto send_done;
	}

	// handle file type  for
	// 1) identified latency writes
	// 2) identified pack writes
	if ((nvm_engine(nvmd, NVM_OPT_ENGINE_LATENCY) ||
	     nvm_engine(nvmd, NVM_OPT_ENGINE_PACK)) && d->ino.fc != FC_EMPTY) {
		DMERR("ino %lu got new fc %d", d->ino.ino, d->ino.fc);
		hint->ino2fc[d->ino.ino] = d->ino.fc;
	}

	/* non-packable file. ignore hint*/
	if(nvm_engine(nvmd, NVM_OPT_ENGINE_PACK) &&
	   !nvm_is_fc_packable(hint->ino2fc[d->ino.ino])) {
		DMDEBUG("non-packable file. ignore hint");
		goto send_done;
	}

	/* non-latency file. ignore hint*/
	if(nvm_engine(nvmd, NVM_OPT_ENGINE_LATENCY) &&
				d->ino.fc == FC_EMPTY &&
				!nvm_is_fc_latency(hint->ino2fc[d->ino.ino])) {
		DMDEBUG("non-latency file. ignore hint");
		goto send_done;
	}

	// insert to hints list
	info = kmalloc(sizeof(struct hint_info), GFP_KERNEL);
	if (!info) {
		DMERR("can't allocate hint info");
		return -ENOMEM;
	}

	memcpy(&info->hint, &d->ino, sizeof(struct ino_hint));
	info->processed  = 0;
	info->is_write   = d->is_write;
	info->flags = d->flags;

	DMDEBUG("about to add hint_info to list. %s %s",
	       (d->flags & HINT_SWAP) ? "SWAP" :
	       (d->flags & HINT_LATENCY)? "LATENCY" : "REGULAR",
	       (d->is_write) ? "WRITE" : "READ");

	spin_lock(&hint->lock);
	list_add_tail(&info->list_member, &hint->hints);
	spin_unlock(&hint->lock);

send_done:
	return 0;
}


/**
 * automatically extract hint from a bio, and send to target.
 * iterate all pages, look into inode. There are several cases:
 * 1) swap - stop and send hint on entire bio (assuming swap LBAs are not mixed
 *    with regular LBAs in one bio)
 *
 * 2) read - go through page and send hint_payload, one for each inode number and
 *    relevant range of LBAs covered by a page
 *
 * 3) write - check if a page is the first sector of a file, classify it and set
 *    in hint. rest same as read
 */
void nvm_bio_hint(struct nvmd *nvmd, struct bio *bio)
{
	enum fclass fc = FC_EMPTY;
	unsigned ino = -1;
	struct page *bv_page;
	struct address_space *mapping;
	struct inode *host;
	struct bio_vec *bvec;
	uint32_t sector_size = nvmd->sector_size;
	uint32_t sectors_count = 0;
	uint32_t lba = 0, bio_len = 0;
	unsigned long prev_ino = -1, first_sector = -1;
	struct hint_payload *d;
	int ret;
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

	d = kzalloc(sizeof(struct hint_payload), GFP_NOIO);
	if (!d) {
		DMERR("hint_payload kmalloc failed");
		return;
	}

	d->lba = lba;
	d->sectors_count = sectors_count;
	d->is_write = is_write;

	DMDEBUG("%s lba=%d sectors_count=%d",
	       is_write ? "WRITE" : "READ",
	       lba, sectors_count);

	bvec = bio_iovec(bio);
	bv_page = bvec->bv_page;

	if (!bv_page || PageSlab(bv_page))
		goto done;

	// swap hint
	if (PageSwapCache(bv_page)) {
		DMDEBUG("swap bio");
		d->flags |= HINT_SWAP;

		d->ino.ino = 0;
		d->ino.start_lba = lba;
		d->ino.count = sectors_count;
		d->ino.fc = fc;
		goto done;
	}

	mapping = page_mapping(bv_page);
	if (!mapping || PageAnon(bv_page))
		goto done;

	host = mapping->host;
	if (!host) {
		DMCRIT("page without mapping->host. shouldn't happen");
		goto done; // no host
	}

	prev_ino = ino;
	ino = host->i_ino;

	if (!host->i_sb || !host->i_sb->s_type || !host->i_sb->s_type->name) {
		DMDEBUG("not related to file system");
		goto done;
	}

	if (!ino) {
		DMDEBUG("not inode related");
		goto done;
	}

	/* classify if we can.
	 * can only classify writes to file's first sector */
	if (is_write && bv_page->index == 0 && bvec->bv_offset == 0) {
		// should be first sector in file. classify
		first_sector = lba + (bio_len / sector_size);
		fc = file_classify(&bvec[0]);
	}

	DMDEBUG("add %s hint here - ino=%u lba=%u fc=%s count=%d",
	       is_write ? "WRITE" : "READ",
	       ino,
	       lba + (bio_len / sector_size),
	       (fc == FC_VIDEO_SLOW) ? "VIDEO" : (fc == FC_EMPTY) ? "EMPTY" : "UNKNOWN",
	       bvec[0].bv_len / sector_size);

	d->ino.ino = ino;
	d->ino.start_lba = lba;
	d->ino.count = 1;
	d->ino.fc = fc;

	ret = nvm_send_hint(nvmd, d);
	if (!ret)
		DMERR("nvm_send_hint error %d", ret);

done:
	kfree(d);
}

static int nvm_read_bio_hint(struct nvmd *nvmd, struct bio *bio)
{
	return nvm_read_bio(nvmd, bio);
}

static void free_shadow_bio(struct nvmd *nvmd, struct bio *shadow_bio, struct page *page);

/* if we ever support trim, this may be unified with some generic function */
static void nvm_trim_map_shadow(struct nvmd *nvmd, sector_t l_addr)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct nvm_block *block;
	struct nvm_addr *gp;

	BUG_ON(l_addr >= nvmd->nr_pages);

	spin_lock(&nvmd->trans_lock);
	gp = &hint->shadow_map[l_addr];
	block = gp->block;

	DMDEBUG("trim old shaddow");
	if (block) {
		BUG_ON(gp->addr >= nvmd->nr_pages);

		invalidate_block_page(nvmd, gp);
		gp->block = 0;
		nvmd->rev_trans_map[gp->addr].addr = LTOP_POISON;
		gp->addr = LTOP_EMPTY;
	}

	spin_unlock(&nvmd->trans_lock);
}


struct nvm_hint_map_private *alloc_latency_hint_data(struct nvmd *nvmd, unsigned long flags, sector_t old_p_addr, struct hint_info *info, struct page *page)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct nvm_hint_map_private *mad = mempool_alloc(hint->map_alloc_pool, GFP_NOIO);

	if (!mad)
		return NULL;

	mad->old_p_addr = old_p_addr;
	mad->flags = flags;
	mad->info = info;
	mad->page = page;

	return mad;
}

static void free_shadow_bio(struct nvmd *nvmd, struct bio *shadow_bio, struct page *page)
{
	if (!shadow_bio)
		return;

	bio_put(shadow_bio);
	mempool_free(page, nvmd->page_pool);
}

static int nvm_write_bio_hint(struct nvmd *nvmd, struct bio *bio)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct hint_info *info = NULL;
	sector_t l_addr = bio->bi_sector / NR_PHY_IN_LOG;
	int ret;

	/* trim old shadow, to avoid inconsistencies.
	   Note - do this here, even before primary is updated, to avoid some nasty races */
	if(nvmd->config.flags & NVM_OPT_ENGINE_LATENCY) {
		//DMERR("nvm_write_bio_hint: trim shadow l_addr %ld", l_addr);
		//nvm_trim_map_shadow(nvmd, l_addr);
	}

	/* extract hint from bio */
	//nvm_bio_hint(nvmd, bio);

	/* Submit bio for all physical addresses*/
	ret = nvm_write_execute_bio(nvmd, bio, 0, NULL, NULL, nvmd->trans_map, 1);
	if (ret) {
		DMERR("nvm_write_bio_hint: discarding shadow write l_addr %ld. ret %d", l_addr, ret);
		goto finished;
	}

	//DMERR("nvm_write_bio_hint: find hint l_addr %ld", l_addr);
	info = nvm_find_hint(nvmd, l_addr, 1);

	/* Got latency hint for l_addr, and allocate bio for shadow write*/
	if (1) {//if (info && info->flags & HINT_LATENCY) {
		nvm_write_execute_bio(nvmd, bio, 0, NULL, NULL, hint->shadow_map, 0);
	}

finished:
	/* Processed entire hint */
	if (info) {
		spin_lock(&hint->lock);
		if (info->processed == info->hint.count) {
			list_del(&info->list_member);
			kfree(info);
		}
		spin_unlock(&hint->lock);
	}

	return DM_MAPIO_SUBMITTED;
}

void nvm_alloc_phys_addr_pack(struct nvmd *nvmd, struct nvm_block *block)
{
	/* pack ap's need an ap not related to any inode*/ 
	if (block_is_full(block)) {
		DMDEBUG("__nvm_alloc_phys_addr - block is full. init ap_hint. block->parent_ap %p", block->ap);
		BUG_ON(!block->ap);
		if (block->ap->hint_private)
			init_ap_hint(block->ap);
		block->ap = NULL;
	}
}

struct nvm_addr *nvm_alloc_phys_pack_addr(struct nvmd *nvmd,
				struct nvm_hint_map_private *map_alloc_data)
{
	struct nvm_ap *ap;
	struct nvm_ap_hint* ap_pack_data = NULL;
	struct nvm_addr *p = NULL;
	struct timeval curr_tv;
	unsigned long diff;
	int i;

	/* find open ap for requested inode number */
	for (i = 0; i < nvmd->nr_pools; i++) {
		ap = &nvmd->aps[i];
		/* not hint related */
		if(!ap->hint_private)
			continue;

		ap_pack_data = ap->hint_private;

		/* got it */
		if (ap_pack_data->ino == map_alloc_data->info->hint.ino) {
			DMDEBUG("ap with block_addr %ld associated to requested inode %d", block_to_addr(ap->cur), ap_pack_data->ino);
			spin_lock(&ap->lock);
			p = nvm_alloc_addr_from_ap(ap, 0);
			spin_unlock(&ap->lock);
			break;
		}
	}

	if (p) {
		DMDEBUG("allocated addr %ld from PREVIOUS associated ap ", addr);
		goto pack_alloc_done;
	}

	/* no ap associated to requested inode.
	   find some empty pack ap, and use it*/
	DMDEBUG("no ap associated to inode %lu", map_alloc_data->info->hint.ino);
	for (i = 0; i < nvmd->nr_pools; i++) {
		ap = get_next_ap(nvmd);

		/* not hint associated */
		if(!ap->hint_private)
			continue;

		ap_pack_data = (struct nvm_ap_hint*)ap->hint_private;

		/* associated to an other inode */
		if(ap_pack_data->ino != INODE_EMPTY &&
		   ap_pack_data->ino != map_alloc_data->info->hint.ino){
			/* check threshold and decide whether to replace associated inode */
			do_gettimeofday(&curr_tv);
			diff = diff_tv(&curr_tv, &ap_pack_data->tv);
			if(AP_DISASSOCIATE_TIME > diff)
				continue;
			DMINFO("ap association timeout expired");
			/* proceed to associate with some other inode*/			
		}

		/* got it - empty ap not associated to any inode */
		ap_pack_data->ino = map_alloc_data->info->hint.ino; // do this before alloc_addr
		spin_lock(&ap->lock);
		p = nvm_alloc_addr_from_ap(ap, 0);
		spin_unlock(&ap->lock);
		DMDEBUG("re-associated ap with block_addr %ld to new inode %d", block_to_addr(ap->cur), ap_pack_data->ino);

		break;
	}

	if (p) {
		DMDEBUG("allocated addr %ld from NEW associated ap ", addr);
		goto pack_alloc_done;
	}

	DMDEBUG("no new/previous ap associated to inode. do regular allocation");
	/* haven't found any relevant/empty pack ap. resort to regular allocation
	   (from non-packed ap)*/
	/* TODO: overtake "regular" ap? return error? */
	do {
		ap = get_next_ap(nvmd);
	} while (ap->hint_private);

	spin_lock(&ap->lock);
	p = nvm_alloc_addr_from_ap(ap, 0);
	spin_unlock(&ap->lock);

pack_alloc_done:
	if (ap_pack_data)
		do_gettimeofday(&ap_pack_data->tv);
	return p;
}

/* Latency-proned Logical to physical address translation.
 *
 * If latency hinted write, write data to two locations, and save extra mapping
 * If non-hinted write - resort to normal allocation
 * if GC write - no hint, but we use regular map_ltop() with GC addr
 */
static struct nvm_addr *nvm_map_pack_hint_ltop_rr(struct nvmd *nvmd,
			sector_t l_addr, int is_gc,
			struct nvm_addr *trans_map, void *private)
{
	struct nvm_hint_map_private *mad = private;
	struct nvm_addr *p;

	/* If there is no hint, or this is a reclaimed ltop mapping,
	 * use regular (single-page) map_ltop */
	if (!mad ||
	    mad->old_p_addr != LTOP_EMPTY ||
	    !mad->info) {
		DMDEBUG("pack_rr: reclaimed or regular allocation");
		return nvm_map_ltop_rr(nvmd, l_addr, 0, nvmd->trans_map, NULL);
	}

	DMDEBUG("pack_ltop: regular request. allocate page");

	/* 1) get addr.
	      nvm_alloc_addr_from_pack_ap, finds ap AND allocates addr*/
	/* FIXME: should rearrange code to take AP lock from here */
	p = nvm_alloc_phys_pack_addr(nvmd, mad);
	if (p) {
		DMDEBUG("pack_rr: for l_addr=%ld allocated p_addr=%ld ",
							l_addr, p->addr);
		nvm_update_map(nvmd, l_addr, p, is_gc, nvmd->trans_map);
	}

	return p;
}

/* Swap-proned Logical to physical address translation.
 *
 * If swap write, use simple fast page allocation - find some append point whose next page is fast.
 * Then update the ap for the next write to the disk.
 * If no reelvant ap found, or non-swap write - resort to normal allocation
 */
static struct nvm_addr *nvm_map_swap_hint_ltop_rr(struct nvmd *nvmd,
				sector_t l_addr, int is_gc,
				struct nvm_addr *trans_map, void *private)
{
	struct nvm_hint_map_private *mad = private;
	struct nvm_addr *p;
	/* Check if there is a hint for relevant sector
	 * if not, resort to nvm_map_ltop_rr */
	if (mad) {
		if (mad->old_p_addr == LTOP_EMPTY &&
				!mad->info) {
			DMDEBUG("swap_map: non-GC non-hinted write");
			return nvm_map_ltop_rr(nvmd, l_addr, 0, nvmd->trans_map, NULL);
		}

		/* GC write of a slow page */
		if (mad->old_p_addr != LTOP_EMPTY &&
				!page_is_fast(nvmd, physical_to_slot(nvmd,
						mad->old_p_addr))) {
			DMDEBUG("swap_map: GC write of a SLOW page (old_p_addr \
				%ld block offset %d)",
					mad->old_p_addr,
					physical_to_slot(nvmd, mad->old_p_addr));
			return nvm_map_ltop_rr(nvmd, l_addr, 0, nvmd->trans_map, NULL);
		}
	}

	//DMINFO("swap_rr: got physical_addr %d *ret_victim_block %p", physical_addr, *ret_victim_block);
	DMDEBUG("write lba %ld to page %ld", l_addr, p->addr);
	nvm_update_map(nvmd, l_addr, p, is_gc, nvmd->trans_map);
	return p;
}

// TODO: actually finding a non-busy pool is not enough. read should be moved up the request queue.
//	 however, no queue maipulation impl. yet...
static struct nvm_addr *nvm_latency_lookup_ltop(struct nvmd *nvmd, sector_t logical_addr)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct nvm_pool *pool;
	struct nvm_addr *shadow_p;

	BUG_ON(!(logical_addr >= 0 && logical_addr < nvmd->nr_pages));

	// shadow is empty
	if (hint->shadow_map[logical_addr].addr == LTOP_EMPTY) {
		DMDEBUG("no shadow. read primary");
		return nvm_lookup_ltop(nvmd, logical_addr);
	}

	// check if primary is busy
	pool = paddr_to_pool(nvmd, nvmd->trans_map[logical_addr].addr);
	if (atomic_read(&pool->is_active)) {
		DMDEBUG("primary busy. read shadow");
		pool = paddr_to_pool(nvmd, nvmd->trans_map[logical_addr].addr);
		if (atomic_read(&pool->is_active))
			goto read_primary;

		shadow_p = nvm_lookup_ltop_map(nvmd, logical_addr, hint->shadow_map);

		/* no address, or empty shadow - default to primary */
		if(!shadow_p || !shadow_p->block)
			goto read_primary;

		return shadow_p;
	}

read_primary:
	return nvm_lookup_ltop(nvmd, logical_addr);
}

static unsigned long nvm_get_mapping_flag(struct nvmd *nvmd, sector_t logical_addr, sector_t old_p_addr)
{
	struct nvm_hint *hint = nvmd->hint_private;
	unsigned long flag = MAP_PRIMARY;

	if (old_p_addr != LTOP_EMPTY) {
		DMDEBUG("get_flag old_p_addr %ld nvmd->trans_map[%ld].addr %ld \
				hint->shadow_map[%ld].addr %ld", old_p_addr,
				logical_addr, nvmd->trans_map[logical_addr].addr, logical_addr, hint->shadow_map[logical_addr].addr);
		spin_lock(&nvmd->trans_lock);
		if (nvmd->trans_map[logical_addr].addr == old_p_addr)
			flag = MAP_PRIMARY;
		else if (hint->shadow_map[logical_addr].addr == old_p_addr)
			flag = MAP_SHADOW;
		else {
			DMERR("Reclaiming a physical page %ld not mapped by any logical addr", old_p_addr);
			WARN_ON(true);
		}
		spin_unlock(&nvmd->trans_lock);
	}

	return flag;
}

int nvm_ioctl_user_hint_cmd(struct nvmd *nvmd, unsigned long arg)
{
	hint_data_t __user *uhint = (hint_data_t*)arg;
	hint_data_t khint;

	if (copy_from_user(&khint, uhint, sizeof(hint_data_t)))
		return -EFAULT;

	return nvm_send_hint(nvmd, CAST_TO_PAYLOAD(&khint));
}

int nvm_ioctl_kernel_hint_cmd(struct nvmd *nvmd, unsigned long arg)
{
	return nvm_send_hint(nvmd, (struct hint_payload *)arg);
}

int nvm_ioctl_hint(struct nvmd *nvmd, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case LIGHTNVM_IOCTL_SUBMIT_HINT:
		return nvm_ioctl_user_hint_cmd(nvmd, arg);
	case LIGHTNVM_IOCTL_KERNEL_HINT:
		return nvm_ioctl_kernel_hint_cmd(nvmd, arg);
	default:
		return 0;
	}
}

int nvm_init_hint(struct nvmd *nvmd)
{
	return 0;
}

int nvm_alloc_hint(struct nvmd *nvmd)
{
	struct nvm_hint *hint;
	struct nvm_ap *ap;
	struct nvm_pool *pool;
	int i;

	hint = kmalloc(sizeof(struct nvm_hint), GFP_KERNEL);
	if (!hint)
		return -ENOMEM;

	hint->shadow_map = vmalloc(sizeof(struct nvm_addr) * nvmd->nr_pages);
	if (!hint->shadow_map)
		goto err_shadow_map;
	memset(hint->shadow_map, 0, sizeof(struct nvm_addr) * nvmd->nr_pages);

	for(i = 0; i < nvmd->nr_pages; i++) {
		struct nvm_addr *p = &hint->shadow_map[i];
		p->addr = LTOP_EMPTY;
		atomic_set(&p->inflight, 0);
	}

	spin_lock_init(&hint->lock);
	INIT_LIST_HEAD(&hint->hints);

	hint->ino2fc = kzalloc(HINT_MAX_INOS, GFP_KERNEL);
	if (!hint->ino2fc)
		goto err_hints;

	_map_alloc_cache = kmem_cache_create("lightnvm_map_alloc_cache",
				sizeof(struct nvm_hint_map_private), 0, 0, NULL);
	hint->map_alloc_pool = mempool_create_slab_pool(16, _map_alloc_cache);

	if (!hint->map_alloc_pool)
		goto err_map_alloc;

	/* mark all pack hint related ap's*/
	ssd_for_each_pool(nvmd, pool, i) {
		unsigned int last_ap;
		/* choose the last ap in each pool */
		last_ap = (i * nvmd->nr_aps_per_pool) + nvmd->nr_aps_per_pool - 1;
		ap = &nvmd->aps[last_ap];

		ap->hint_private = kmalloc(sizeof(struct nvm_ap_hint),
								GFP_KERNEL);
		if (!ap->hint_private) {
			DMERR("Couldn't allocate hint private for ap.");
			goto err_ap_hints;
		}
		init_ap_hint(ap);
	}

	if (nvmd->config.flags & NVM_OPT_ENGINE_SWAP) {
		DMINFO("Swap hint support");
		nvmd->map_ltop = nvm_map_swap_hint_ltop_rr;
		nvmd->write_bio = nvm_write_bio_hint;
		nvmd->read_bio = nvm_read_bio_hint;
	} else if (nvmd->config.flags & NVM_OPT_ENGINE_LATENCY) {
		DMINFO("Latency hint support");
		nvmd->lookup_ltop = nvm_latency_lookup_ltop;
		nvmd->write_bio = nvm_write_bio_hint;
		nvmd->read_bio = nvm_read_bio_hint;
		nvmd->defer_bio = nvm_hint_defer_bio;
	} else if (nvmd->config.flags & NVM_OPT_ENGINE_PACK) {
		DMINFO("Pack hint support");
		nvmd->map_ltop = nvm_map_pack_hint_ltop_rr;
		nvmd->alloc_phys_addr = nvm_alloc_phys_addr_pack;
		nvmd->write_bio = nvm_write_bio_hint;
		nvmd->read_bio = nvm_read_bio_hint;

		if (nvmd->nr_aps_per_pool < 2 ) {
			DMERR("Need at least 2 aps for pack hints");
			goto err_hints;
		}
	}

	nvmd->hint_private = hint;

	return 0;
err_ap_hints:
	ssd_for_each_ap(nvmd, ap, i)
		kfree(ap->hint_private);
	mempool_destroy(hint->map_alloc_pool);
err_map_alloc:
	kfree(hint->ino2fc);		
err_hints:
	vfree(hint->shadow_map);
err_shadow_map:
	kfree(hint);
	return -ENOMEM;
}

void nvm_free_hint(struct nvmd *nvmd)
{
	struct nvm_hint *hint = nvmd->hint_private;
	struct hint_info *info, *next_info;
	struct nvm_ap *ap;
	int i;

	spin_lock(&hint->lock);
	list_for_each_entry_safe(info, next_info, &hint->hints, list_member) {
		list_del(&info->list_member);
		kfree(info);
	}
	spin_unlock(&hint->lock);

	kfree(hint->ino2fc);
	vfree(hint->shadow_map);

	/* mark all pack hint related ap's*/
	ssd_for_each_ap(nvmd, ap, i)
		kfree(ap->hint_private);

	mempool_destroy(hint->map_alloc_pool);

	kfree(nvmd->hint_private);
}

void nvm_exit_hint(struct nvmd *nvmd)
{
	// release everything else needed
}
