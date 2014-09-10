/*
 * Definitions for the LightNVM host interface
 * Copyright (c) 2014, IT University of Copenhagen, Matias Bjorling.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef _UAPI_LINUX_OPENVSL_H
#define _UAPI_LINUX_OPENVSL_H

#include <linux/types.h>

enum {
	OPENVSL_KV_GET		= 0x00,
	OPENVSL_KV_PUT		= 0x01,
	OPENVSL_KV_UPDATE	= 0x02,
	OPENVSL_KV_DEL		= 0x03,
};


struct openvsl_cmd_kv {
	__u8		opcode;
	__u8		res[7];
	__u32		key_len;
	__u32		val_len;
	__u64		key_addr;
	__u64		val_addr;
};

#define OPENVSL_IOCTL_ID	_IO('O', 0x40)
#define OPENVSL_IOCTL_KV	_IOWR('O', 0x50, struct openvsl_cmd_kv)

#endif /* _UAPI_LINUX_OPENVSL_H */
