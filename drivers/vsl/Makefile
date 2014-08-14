#
# Makefile for OpenVSL.
#

#Enable to enable additional debugging-checks
DEBUG=y

ifeq ($(DEBUG),y)
  CFLAGS += -O -g -DVSL_DEBUG
endif

obj-$(CONFIG_OPENVSL)		+= vsl.o core.o gc.o sysfs.o vslkv.o vsltgt.o
