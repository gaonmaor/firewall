# The binaries assembled for the module.
FWMOD_FILES := firewall.o connection_table.o tcp_conn_handler.o sqli.o zabbix.o http_protections.o pm.o hash_table.o

MAKE        := make
MOD_NAME    := fw5
KERN_OBJS   := $(patsubst %,$(KERNEL_ODIR)/%,$(FWMOD_FILES))
KERNEL_DIR  := /lib/modules/$(shell uname -r)/build

ifneq ($(KERNELRELEASE),)
obj-m            += $(MOD_NAME).o
$(MOD_NAME)-y    := $(FWMOD_FILES)
else
.PHONY: clean all debug

all:
	make clean modules

modules: $(KERNEL_OUT)
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) modules
endif

clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(CURDIR) clean
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions

