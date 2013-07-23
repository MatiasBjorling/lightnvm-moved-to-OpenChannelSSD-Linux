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

#endif /* DM_OPENSSD_H_ */
