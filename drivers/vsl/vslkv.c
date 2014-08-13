#include "vsl.h"

int vslkv_unpack(struct vsl_dev *dev, struct vsl_cmd_kv __user *ucmd)
{
	struct vsl_cmd_kv cmd;

	if(copy_from_user(&cmd, ucmd, sizeof(cmd)))
		return -EFAULT;
	switch(cmd.opcode) {
	case VSL_KV_GET:
	case VSL_KV_PUT:
	case VSL_KV_UPDATE:
	case VSL_KV_DEL:
	default:
		return -1;
	}
}
