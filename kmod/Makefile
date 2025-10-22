obj-m += binfmt_lc64.o
KERNEL_VERSION=`uname -r`
.PHONY: all
all:
	make -C /lib/modules/$(KERNEL_VERSION)/build "M=`pwd`" modules
