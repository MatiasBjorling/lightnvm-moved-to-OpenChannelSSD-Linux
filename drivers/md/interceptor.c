/*
 * simple system call interceptor. based on code from
 * bbs.archlinux.org/viewtopic.php?id=139406
 * a hint advice is a file class (see dm-openssd-hint.h) offseted by 16 bits to differentiate
 * from "real" advices (0-7)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/blkdev.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/syscalls.h>
#include <asm/unistd.h>
#include <linux/fadvise.h>
#include "dm-openssd-hint.h"
#include "dm-openssd.h"

unsigned long **sys_call_table;

asmlinkage long (*ref_sys_fadvise64)(int fd, loff_t offset, loff_t len, int advice);

asmlinkage long new_sys_fadvise64(int fd, loff_t offset, loff_t len, int advice)
{
    struct fd f = fdget(fd);
    struct address_space *mapping;
    int ret = 0;
    hint_data_t *hint_data;
    int max = POSIX_FADV_NOREUSE;
    int hint_advice = advice >> 16;
    struct block_device* bdev;

    //printk("*** fadvise intercepted. \n");
    //printk(KERN_INFO "fd=%d offset=%lld len=%lld advice=%d (%d)\n", fd, offset, len, advice, hint_advice);    

    // non-hint fadvice
    // do original fadvise
    if(advice < max){
       return ref_sys_fadvise64(fd, offset, len, advice);
    }

    // sanity checks from original fadvise code
    if (!f.file){
        printk( "bad file\n");
        return -EBADF;
    }

    if (S_ISFIFO(f.file->f_path.dentry->d_inode->i_mode)) {
        printk( "file is fifo\n");
        ret = -ESPIPE;
        goto out;
    }
 
    mapping = f.file->f_mapping;
    if (!mapping || len < 0) {
        printk( "mapping=%p len=%lld\n", mapping, len);
        ret = -EINVAL;
        goto out;
    }

    // use block device from file's superblock
    bdev = mapping->host->i_sb->s_bdev;
    hint_data = kmalloc(sizeof(hint_data_t), GFP_ATOMIC);

    if(!hint_data){
        printk( "failed kmalloc()\n");
        return -1;
    };

    // set page hint_data fields
    // for now send mock hint0.
    switch (hint_advice) {
        case FC_UNKNOWN:
        case FC_VIDEO_SLOW:
            memset(hint_data, 0x00, sizeof(hint_data_t));
            /* we dont know the actual relevant LBAs, so use LBA 0 and 4K lengtgh...*/
            CAST_TO_PAYLOAD(hint_data)->lba = 0;
            CAST_TO_PAYLOAD(hint_data)->sectors_count = bdev_physical_block_size(bdev);
            CAST_TO_PAYLOAD(hint_data)->is_write = 1;
            INO_HINT_SET(hint_data, CAST_TO_PAYLOAD(hint_data)->count,
                         mapping->host->i_ino, 
                         CAST_TO_PAYLOAD(hint_data)->lba, 
                         CAST_TO_PAYLOAD(hint_data)->sectors_count, 
                         hint_advice); 
            CAST_TO_PAYLOAD(hint_data)->count++;
            //printk("ioctl %x to device\n", OPENSSD_IOCTL_SUBMIT_HINT);
            return ioctl_by_bdev(bdev, OPENSSD_IOCTL_KERNEL_HINT, (unsigned long)hint_data);
            break;
        default:
            ret = -EINVAL;
            goto out;
    }
out:
    fdput(f);
    return ret;
}

static unsigned long **aquire_sys_call_table(void)
{
   unsigned long int offset = PAGE_OFFSET;
   unsigned long **sct;

   while (offset < ULLONG_MAX) {
      sct = (unsigned long **)offset;

      if (sct[__NR_close] == (unsigned long *) sys_close) 
         return sct;

      offset += sizeof(void *);
   }

   return NULL;
}

static void disable_page_protection(void) 
{
   unsigned long value;
   asm volatile("mov %%cr0, %0" : "=r" (value));

   if(!(value & 0x00010000))
      return;

   asm volatile("mov %0, %%cr0" : : "r" (value & ~0x00010000));
}

static void enable_page_protection(void) 
{
   unsigned long value;
   asm volatile("mov %%cr0, %0" : "=r" (value));

   if((value & 0x00010000))
      return;

   asm volatile("mov %0, %%cr0" : : "r" (value | 0x00010000));
}

static int __init interceptor_start(void) 
{
   if(!(sys_call_table = aquire_sys_call_table()))
      return -1;

   disable_page_protection();
   ref_sys_fadvise64 = (void *)sys_call_table[__NR_fadvise64];
   sys_call_table[__NR_fadvise64] = (unsigned long *)new_sys_fadvise64;
   enable_page_protection();

   printk( "fadvise interceptor loaded\n");
   return 0;
}

static void __exit interceptor_end(void) 
{
   if(!sys_call_table)
      return;

   disable_page_protection();
   sys_call_table[__NR_fadvise64] = (unsigned long *)ref_sys_fadvise64;
   enable_page_protection();

   printk( "fadvise interceptor unloaded\n");
}

module_init(interceptor_start);
module_exit(interceptor_end);
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("system call interceptor");
