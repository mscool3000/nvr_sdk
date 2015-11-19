
TARGET_DIR = $(COMM_APPS_DIR)/nc_ipcs_sdk/inst

_SRCS := $(wildcard *.c)
_OBJS := $(_SRCS:%.c=%.o)

DSTLIB = $(TARGET_DIR)/lib
DSTINC = $(TARGET_DIR)/include
#TARGET = arp_listen
TARGET2 = libnc_ipcs_sdk.so
TARGET3 = libnc_ipcs_sdk.a
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
AR = $(CROSS_COMPILE)ar
CFLAGS = $(CROSS_EXTRA_CFLAGS) -g -fPIC -DWITH_OPENSSL -DWHITH_DOM \
				 -DNETCORETEC_NVR -DWITH_NONAMESPACES \
				 -I$(COMM_APPS_DIR)/nc_onvif_client/inst/include \
				 -I$(COMM_APPS_DIR)/openssl/inst/include \
				 -I$(COMM_APPS_DIR)/openssl/inst/include/openssl \
				 -I../nc_arp  -I../nc_dhcp

LDFLAGS = -L$(COMM_APPS_DIR)/nc_onvif_client/inst/lib -linterface \
					-L$(COMM_APPS_DIR)/openssl/inst/lib -lssl -lcrypto \
					-L$(COMM_APPS_DIR)/switch/inst/lib -lnc_switch \
          -ldl -lrt -lm -lpthread
ARFLAGS = cr
SHAREFLAGS = -fPIC -shared

romfs: $(TARGET2)  $(TARGET3)
	$(STRIP) $(TARGET2)
	cp $(TARGET2) $(DSTLIB)
	cp $(TARGET3) $(DSTLIB)
	cp *.h $(DSTINC)
$.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
$(TARGET2): $(_OBJS)
	$(CC) $(SHAREFLAGS) -o $@ $(_OBJS)
$(TARGET3): $(_OBJS)
	$(AR) $(ARFLAGS) $@ $(_OBJS)

	


 


clean:
	@$(RM) $(_OBJS) $(TARGET2) $(TARGET3) $(ORIG_FILES) *.bak *~ 
