
obj-m = hintdm.o
hintdm-y := dm-openssd-pool.o dm-openssd.o

PWD = $(shell pwd)
KVERSION = $(shell uname -r)

all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) clean
