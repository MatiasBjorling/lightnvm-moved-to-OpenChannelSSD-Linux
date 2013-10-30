/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef DM_OPENSSD_HINT_H_
#define DM_OPENSSD_HINT_H_

#include <linux/types.h>
#include "dm-openssd.h"

#define OPENSSD_IOCTL_SUBMIT_HINT _IOW(OPENSSD_IOC_MAGIC, 0x41, hint_data_t)
#define OPENSSD_IOCTL_KERNEL_HINT _IOW(OPENSSD_IOC_MAGIC, 0x42, hint_data_t)

#define HINT_MAX_INOS       (500000)
#define HINT_DATA_MAX_INOS  (8)
#define HINT_DATA_SIZE (HINT_DATA_MAX_INOS*128) /* > 16 * 128 files at most */
#define GET_HINT_FROM_PAYLOAD(PAYLOAD, IDX) (((ino_hint_t*)((PAYLOAD)->data))[IDX])
#define CAST_TO_PAYLOAD(HINT_DATA) ((hint_payload_t*)((HINT_DATA)->hint_payload))
#define INO_HINT_FROM_DATA(HINT_DATA, IDX) ((ino_hint_t*)(CAST_TO_PAYLOAD(HINT_DATA)->data))[IDX]
#define INO_HINT_SET(HINT_DATA, IDX, INO, START, COUNT, FC) \
			     INO_HINT_FROM_DATA(HINT_DATA, IDX).ino = INO; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).start_lba = START; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).count = COUNT; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).fc = FC;
typedef enum {
	FC_EMPTY,
	FC_UNKNOWN,
	FC_VIDEO_SLOW,
	FC_IMAGE_SLOW,
	FC_DB_INDEX
} fclass;

typedef struct ino_hint_s {
	unsigned long ino; // inode number
	uint32_t start_lba; // start lba relevant in sc
	uint32_t count; //number of sequential lba's related to ino (starting from start_lba)
	fclass fc;
} ino_hint_t;

typedef struct hint_payload_s {
	char     data[HINT_DATA_SIZE];
	uint32_t is_write;
	uint32_t hint_flags;
	uint32_t lba;
	uint32_t sectors_count;
	uint32_t count; // number of ino_hint_t in data
} hint_payload_t;

#define HINT_PAYLOAD_SIZE sizeof(hint_payload_t)

typedef struct hint_data_s {
	uint32_t hint_payload_size;
	char hint_payload[HINT_PAYLOAD_SIZE];
} hint_data_t;

#ifdef __KERNEL__
struct openssd_hint {
	unsigned int hint_flags;
	char* ino2fc; // TODO: 500k inodes == ~0.5MB. for extra-efficiency use hash/bits table
	spinlock_t hintlock;
	struct list_head hintlist;
	struct nvm_addr *shadow_map; // TODO should be hash table for efficiency? (but then we also need to use a lock...)
};

typedef struct hint_info_s {
	ino_hint_t hint; // if NULL, none
	char is_write;
	unsigned int hint_flags;
	uint32_t processed; // how many related LBAs were indeed processed
	struct list_head list_member;
} hint_info_t;

struct openssd_hint_map_private {
	sector_t old_p_addr;
	struct nvm_ap *prev_ap;
	unsigned long flags;
	hint_info_t *hint_info;
};
struct openssd_ap_hint {
	unsigned int ino;
	struct timeval tv; // time of last allocation in this ap
};

#define AP_DISASSOCIATE_TIME 10000 // permit disassociation of ap to inode after X us. XXX is 10ms right?
#define INODE_EMPTY -1

static inline void init_ap_hint(struct nvm_ap *ap)
{
	((struct openssd_ap_hint*)ap->hint_private)->ino = INODE_EMPTY;
}
#endif

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
	 ((HINT_INFO)->hint_flags & FLAGS))

#endif /* DM_OPENSSD_HINT_H_ */
