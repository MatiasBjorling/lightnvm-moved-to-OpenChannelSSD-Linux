/*
 * process and submit request composed of bio's, with hints on file-relation
 * (21.7.2013) - each line is of the format <time,rw,inode,lba,sectors,type>
 * time - from trace start 
 * rw - read/write call (R=read, W=write)
 * inode - number of realted inode
 * lba - start lba (512 sectors)
 * sectors - number of sectors to r/w
 * type - type of I/O (S=swap, R=regular, F=regular file first sector)
 * 
 * each line represents a bio, potentially part of same request. 
 * we cluster each such bios to one I/O request, and pre-send a relevant hint (using special ioctl
 * that dm-openssd knows)
 *
 * example trace (verified on dm-openssd):
 * 132764.64756 W 1000 1024 64 F
 * 132764.64756 W 3529 1096 8 R
 * 232764.64757 R 3529 3324 24 F
 * 432764.64758 W 3529 4432 32 R
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

#include <sys/types.h>
#include <fcntl.h> // for open flags
#include <assert.h>
#include <errno.h> 
#include <string.h>
#include <inttypes.h>
#include <sys/ioctl.h>

#define MAX_REQUEST_SIZE (1024*1024)
#define SECTOR_SIZE (512) 
#include "dm-openssd.h"

#ifdef DEBUG
#define DBGPRINT(fmt, ...) printf(fmt, ## __VA_ARGS__)
#else
#define DBGPRINT(fmt, ...) 
#endif

int send_hint_bio(int dev_fd, hint_data_t *hint_data, char *buf){
    int ret;

    // send hint ioctl (if necessary)
    ret = ioctl(dev_fd, OPENSSD_IOCTL_SUBMIT_HINT, hint_data); // ioctl
    if(ret < 0){
        perror("ioctl");
        exit(-1);
    }

    // do real I/O
    DBGPRINT("%s %d bytes to offset %d (lba %d)\n", 
            (CAST_TO_PAYLOAD(hint_data)->is_write)?"WRITE":"READ",
            CAST_TO_PAYLOAD(hint_data)->sectors_count * SECTOR_SIZE, 
            CAST_TO_PAYLOAD(hint_data)->lba * SECTOR_SIZE, CAST_TO_PAYLOAD(hint_data)->lba);

    assert(CAST_TO_PAYLOAD(hint_data)->lba * SECTOR_SIZE == lseek(dev_fd, CAST_TO_PAYLOAD(hint_data)->lba * SECTOR_SIZE, SEEK_SET));
    if(CAST_TO_PAYLOAD(hint_data)->is_write){
        assert(CAST_TO_PAYLOAD(hint_data)->sectors_count * SECTOR_SIZE == write(dev_fd, buf, CAST_TO_PAYLOAD(hint_data)->sectors_count * SECTOR_SIZE));
    }
    else{
        assert(CAST_TO_PAYLOAD(hint_data)->sectors_count * SECTOR_SIZE == read(dev_fd, buf, CAST_TO_PAYLOAD(hint_data)->sectors_count * SECTOR_SIZE));
    }

    if(ret<0){
        perror("I/O error");
        return -1;
    }

    return 0;
}

int main(int argc, char** argv){
    int i, dev_fd, ret;
    char buf[MAX_REQUEST_SIZE];
    float time = -1.0, prev_time;
    char operation[64];
    int inode;
    int lba;
    int sectors_count;   
    char type[64];
    hint_data_t hint_data;
    fclass fc;

    if ( argc != 3){
        printf("usage: hinttrace <trace file> <device>\n");
        return -1;
    }

    // initialize buffer in some form
    for(i=0;i<MAX_REQUEST_SIZE;i++) buf[i] = 'a'; // XXX make random content

    // open device
    DBGPRINT("opening device %s\n", argv[2]);
    dev_fd = open(argv[2], O_RDWR);
    assert(dev_fd>=0);

    char* filename = argv[1];
    DBGPRINT("opening trace file %s\n", filename);
    FILE *file = fopen ( filename, "r" );
    assert( file != NULL );

    // read line by line
    char line[1024]; 
    while(fgets(line, 1024, file) != NULL ){
        // scan trace line
        prev_time = time;
        DBGPRINT(">>> execute line %s\n", line); // 132764.64756,W,3529,0,8,R
        ret = sscanf(line, "%f %s %d %d %d %s", &time,operation,&inode,&lba, &sectors_count,type);
        if(ret < 6){
            DBGPRINT("ERROR - line scan ret=%d\n", ret);
            break;
        }
        DBGPRINT("time %f op %s inode %d lba %d sectors_count %d type %s\n",
                time,operation,inode,lba,sectors_count,type);        

        // new request. send previous hints and bio's
        // TODO: wait til next request time? ot just send?
        if(time != prev_time){
            if(prev_time >= 0.0){
                ret = send_hint_bio(dev_fd, &hint_data, buf);

                if(ret < 0){
                    perror("send_hint_bio");
                    exit(-1);
                }
            }
            // init new hint
            memset(&hint_data, 0, sizeof(hint_data_t));
            CAST_TO_PAYLOAD(&hint_data)->lba = lba;
            CAST_TO_PAYLOAD(&hint_data)->sectors_count = sectors_count;
            CAST_TO_PAYLOAD(&hint_data)->is_write = (!strcmp(operation, "W"))?1:0;
            CAST_TO_PAYLOAD(&hint_data)->is_swap = (!strcmp(operation, "S"))?1:0;

            // assume all files are video slow
            // TODO: future traces may include file type themselves...
            fc = FC_EMPTY;
            if(inode > 0 && !strcmp(type,"F"))
                fc = FC_VIDEO_SLOW;

            DBGPRINT("set hint 0 - fc=%d (swap=%d write=%d) lba %d sectors_count %d\n", 
                    fc, CAST_TO_PAYLOAD(&hint_data)->is_swap, CAST_TO_PAYLOAD(&hint_data)->is_write,
                    lba, sectors_count);
            INO_HINT_SET(&hint_data, CAST_TO_PAYLOAD(&hint_data)->count, 
                         inode, lba, sectors_count, fc);
            CAST_TO_PAYLOAD(&hint_data)->count++;
            continue;
        }

        // another bio with same time as prev_time. update hint accordingly
        CAST_TO_PAYLOAD(&hint_data)->sectors_count += sectors_count;
        DBGPRINT("set hint %d - fc=%d (swap=%d write=%d) lba %d sectors_count %d\n", 
                CAST_TO_PAYLOAD(&hint_data)->count,
                fc, CAST_TO_PAYLOAD(&hint_data)->is_swap, CAST_TO_PAYLOAD(&hint_data)->is_write,
                lba, sectors_count);
        INO_HINT_SET(&hint_data, CAST_TO_PAYLOAD(&hint_data)->count, 
                     inode, lba, sectors_count, fc);
        CAST_TO_PAYLOAD(&hint_data)->count++;
    }

    // send last hint and request
    ret = send_hint_bio(dev_fd, &hint_data, buf);
    if(ret < 0){
        perror("send_hint_bio");
        exit(-1);
    }

    // close files 
    DBGPRINT("closing file...\n");
    sleep(1);
    fclose(file);
    assert(!close(dev_fd));
         
    return 0;
}
