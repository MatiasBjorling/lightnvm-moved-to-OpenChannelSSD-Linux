/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#ifndef DM_OPENSSD_HINT_H_
#define DM_OPENSSD_HINT_H_

#define MAX_CDB_SIZE 16
#define HINT_DATA_MAX_INOS  (8)
#define HINT_DATA_SIZE (HINT_DATA_MAX_INOS*128) /* > 16 * 128 files at most */
#define GET_HINT_FROM_PAYLOAD(PAYLOAD, IDX) (((ino_hint_t*)((PAYLOAD)->data))[IDX])
#define CAST_TO_PAYLOAD(HINT_DATA) ((hint_payload_t*)((HINT_DATA)->hint_payload))
#define INO_HINT_FROM_DATA(HINT_DATA, IDX) ((ino_hint_t*)(CAST_TO_PAYLOAD(HINT_DATA)->data))[IDX]
#define INO_HINT_SET(HINT_DATA, IDX, INO, START, COUNT, FC)  INO_HINT_FROM_DATA(HINT_DATA, IDX).ino = INO; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).start_lba = START; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).count = COUNT; \
                             INO_HINT_FROM_DATA(HINT_DATA, IDX).fc = FC; 
typedef enum {
  FC_EMPTY,
  FC_UNKNOWN,
  FC_VIDEO_SLOW,
  FC_IMAGE_SLOW
} fclass;

typedef struct ino_hint_s {
  unsigned long ino; // inode number
  uint32_t start_lba; // start lba relevant in sc
  uint32_t  count; //number of sequential lba's related to ino (starting from start_lba)
  fclass fc;
} ino_hint_t;

typedef struct hint_payload_s{
   uint32_t is_write; // TODO should really be small flags
   uint32_t is_swap; 
   char data[HINT_DATA_SIZE];
   uint32_t lba;
   uint32_t sectors_count;
   uint32_t count; // number of ino_hint_t in data
}hint_payload_t;

#define HINT_PAYLOAD_SIZE sizeof(hint_payload_t)

typedef struct hint_data_s {
  unsigned int lun;
  char cdb[MAX_CDB_SIZE];
  uint32_t hint_payload_size;
  char hint_payload[HINT_PAYLOAD_SIZE];
} hint_data_t;

#endif /* DM_OPENSSD_HINT_H_ */
