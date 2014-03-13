/*
 * Copyright (C) 2014 Aviad Zuck.
 *
 * This file is released under the GPL.
 */

#ifndef DM_LIGHTNVM_HINT_H_
#define DM_LIGHTNVM_HINT_H_

#include <linux/types.h>
#include "lightnvm.h"

#define LIGHTNVM_IOCTL_SUBMIT_HINT _IOW(LIGHTNVM_IOC_MAGIC, 0x41, struct hint_payload)
#define LIGHTNVM_IOCTL_KERNEL_HINT _IOW(LIGHTNVM_IOC_MAGIC, 0x42, struct hint_payload)

#define HINT_MAX_INOS       (500000)
#define HINT_DATA_MAX_INOS  (8)
#define HINT_DATA_SIZE (HINT_DATA_MAX_INOS * 128) /* > 16 * 128 files at most */

#define GET_HINT_FROM_PAYLOAD(PAYLOAD, IDX) (((struct ino_hint*)(PAYLOAD)->data))[IDX])
#define CAST_TO_PAYLOAD(HINT_DATA) ((struct hint_payload*)((HINT_DATA)->hint_payload))
#define INO_HINT_FROM_DATA(HINT_DATA, IDX) ((CAST_TO_PAYLOAD(HINT_DATA))->ino)
#define INO_HINT_SET(HINT_DATA, IDX, INO, START, COUNT, FC) \
			     INO_HINT_FROM_DATA(HINT_DATA, IDX).ino = INO; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).start_lba = START; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).count = COUNT; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).fc = FC;

#define NVM_PRIO_READ 0x12121212

enum fclass {
	FC_EMPTY,
	FC_UNKNOWN,
	FC_VIDEO_SLOW,
	FC_IMAGE_SLOW,
	FC_DB_INDEX
};

struct ino_hint {
	unsigned long ino; // inode number
	uint32_t start_lba; // start lba relevant in sc
	uint32_t count; //number of sequential lba's related to ino (starting from start_lba)
	enum fclass fc;
};

struct hint_payload {
	uint32_t is_write;
	uint32_t flags;
	uint32_t lba;
	uint32_t sectors_count;
	struct ino_hint ino;
};

#define HINT_PAYLOAD_SIZE sizeof(struct hint_payload)

typedef struct hint_data_s {
	uint32_t hint_payload_size;
	char hint_payload[HINT_PAYLOAD_SIZE];
} hint_data_t;

#ifdef __KERNEL__
struct nvm_hint {
	unsigned int flags;
	char *ino2fc;
	spinlock_t lock;
	struct list_head hints;
	struct nvm_addr *shadow_map;

	mempool_t *map_alloc_pool;

	/* in-flight data lookup, lookup by logical address. Remember the
	 * overhead of cachelines being used. Keep it low for better cache
	 * utilization. */
	struct nvm_inflight inflight[NVM_INFLIGHT_PARTITIONS];
};

struct hint_info {
	struct ino_hint hint; // if NULL, none
	char is_write;
	unsigned int flags;
	uint32_t processed; // how many related LBAs were indeed processed
	struct list_head list_member;
};

struct nvm_hint_map_private {
	sector_t old_p_addr;
	struct nvm_ap *prev_ap;
	unsigned long flags;
	struct hint_info *info;
	struct page *page;
};

struct nvm_ap_hint {
	unsigned int ino;
	struct timeval tv; // time of last allocation in this ap
};

struct nvm_pool_hint {
	int time_to_wait;
};

#define AP_DISASSOCIATE_TIME 10000 // permit disassociation of ap to inode after X us. XXX is 10ms right?
#define INODE_EMPTY -1

static inline void init_ap_hint(struct nvm_ap *ap)
{
	struct nvm_ap_hint *ap_hint = ap->private;
	ap_hint->ino = INODE_EMPTY;
}

static inline void init_pool_hint(struct nvm_pool *pool)
{
	struct nvm_pool_hint *p = pool->private;
	p->time_to_wait = 0;
}

#endif

/* make sure these follow target_flags defined in dm-openssd.h */
enum deploy_hint_flags {
	HINT_NONE	= 0 << 0, /* No hints applied */
	HINT_SWAP	= 1 << 0, /* Swap aware hints. Detected from block request type */
	HINT_IOCTL	= 1 << 1, /* IOCTL aware hints. Applications may submit direct hints */
	HINT_LATENCY	= 1 << 2, /* Latency aware hints. Detected from file type or durectly from app */
	HINT_PACK	= 1 << 3, /* Acess pattern aware hints for slow sequential files. Detected from file type or directly from app */
};

// r/w matches, and LBA is in lba range of hint
#define is_hint_relevant(LBA, HINT_INFO, IS_WRITE, FLAGS) \
	((HINT_INFO)->is_write == (IS_WRITE) && \
	 (LBA) >= (HINT_INFO)->hint.start_lba && \
	 (LBA) <  ((HINT_INFO)->hint.start_lba+(HINT_INFO)->hint.count) && \
	 ((HINT_INFO)->flags & FLAGS) && \
	 (HINT_INFO)->processed < (HINT_INFO)->hint.count) // not optimal, but at least prevent double frees

#define nvm_engine(nvmd, engine) (nvmd->config.flags & engine)

struct nvm_addr *nvm_hint_get_map(struct nvmd *nvmd, void *private);
void nvm_hint_defer_write_bio(struct nvmd *nvmd, struct bio *bio, void *private);
void nvm_bio_wait_add_prio(struct bio_list *bl, struct bio *bio, void *p_private);

#endif /* DM_LIGHTNVM_HINT_H_ */
