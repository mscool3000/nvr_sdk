SHELL=/bin/bash


INST=$(COMM_APPS_DIR)/libnc_nvr_new/inst

ARP=$(shell find nc_arp -name \*.c)
ARP_OBJS=$(ARP:%.c=%.o)
__OBJS += $(ARP_OBJS)

DHCP=$(shell find nc_dhcp -name \*.c)
DHCP_OBJS=$(DHCP:%.c=%.o)
__OBJS += $(DHCP_OBJS)

SDK=$(shell find nc_ipcs_sdk -name \*.c)
SDK_OBJS=$(SDK:%.c=%.o)
__OBJS += $(SDK_OBJS)

TARGET1 = libnc_nvr.so
TARGET2 = libnc_nvr.a

CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
AR = $(CROSS_COMPILE)ar
ARFLAGS=cr
SHAREFLAGS = -fPIC -shared

CFLAGS = $(CROSS_EXTRA_CFLAGS) -g -fPIC -DWITH_OPENSSL -DWHITH_DOM \
				 -DNETCORETEC_NVR -DWITH_NONAMESPACES \
				 -I./nc_arp  -I./nc_dhcp -I./nc_ipcs_sdk



MV_HEAD_FILES = ./nc_ipcs_sdk/nc_nvr_sdk.h 
MV_LIB=./libnc_nvr.a ./libnc_nvr.so
MV_HEAD_DIR=$(INST)/include
MV_LIB_DIR=$(INST)/lib


romfs: all
	$(STRIP) $(TARGET1)
	cp $(MV_LIB) $(MV_LIB_DIR)
	cp $(MV_HEAD_FILES) $(MV_HEAD_DIR)
all: $(TARGET2) $(TARGET1)
%.o: %.c
	-astyle --style=ansi $< && rm -rf *.orig
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET2):$(__OBJS)
	$(AR) $(ARFLAGS) $@ $(__OBJS) 
$(TARGET1):$(__OBJS) 
	$(CC) $(SHAREFLAGS) -o $@ $(__OBJS)

clean:
	$(RM) $(__OBJS) $(TARGET1) $(TARGET2) nc_arp/*.orig nc_dhcp/*.orig nc_ipcs_sdk/*.orig
