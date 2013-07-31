/*
 * Copyright (C) 2012 Matias Bjørling.
 *
 * This file is released under the GPL.
 */

#include "dm-openssd-hint.h"


#ifndef DM_OPENSSD_H_
#define DM_OPENSSD_H_

#define OPENSSD_IOC_MAGIC 'O'

#define OPENSSD_IOCTL_ID          _IO(OPENSSD_IOC_MAGIC, 0x40)
#define OPENSSD_IOCTL_SUBMIT_HINT _IOW(OPENSSD_IOC_MAGIC, 0x41, hint_data_t)
#define OPENSSD_IOCTL_KERNEL_HINT _IOW(OPENSSD_IOC_MAGIC, 0x42, hint_data_t)

#define ssd_for_each_pool(openssd, pool, i)									\
		for ((i) = 0, pool = &(openssd)->pools[0];							\
			 (i) < (openssd)->nr_pools; (i)++, pool = &(openssd)->pools[(i)])

#define ssd_for_each_ap(openssd, ap, i)										\
		for ((i) = 0, ap = &(openssd)->aps[0];								\
			 (i) < (openssd)->nr_aps; (i)++, ap = &(openssd)->aps[(i)])

#define pool_for_each_block(pool, block, i)									\
		for ((i) = 0, block = &(pool)->blocks[0];							\
			 (i) < (pool)->nr_blocks; (i)++, block = &(pool)->blocks[(i)])


#endif /* DM_OPENSSD_H_ */
