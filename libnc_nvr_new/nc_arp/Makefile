
TARGET_DIR = $(COMM_APPS_DIR)/nc_ipcs_sdk/inst

_SRCS := $(wildcard *.c)
_OBJS := $(_SRCS:%.c=%.o)

DSTLIB = $(TARGET_DIR)/lib
DSTINC = $(TARGET_DIR)/include
TARGET = arp_listen
TARGET2 = libarp_listen.so
TARGET3 = libarp_listen.a
CC = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
AR = $(CROSS_COMPILE)ar
CFLAGS = $(CROSS_EXTRA_CFLAGS) -g -fPIC -DWITH_OPENSSL -DWHITH_DOM \
				 -DNETCORETEC_NVR -DWITH_NONAMESPACES  -I. 

LDFLAGS = -ldl -lrt -lm -lpthread

ARFLAGS = cr
SHAREFLAGS = -fPIC -shared
#$(TARGET2)  $(TARGET3)


romfs: $(TARGET) 	
	$(STRIP) $(TARGET)
	cp $(TARGET) $(ROMFSDIR)/bin
	#$(STRIP) $(TARGET2)
	#cp $(TARGET2) $(DSTLIB)
	#cp $(TARGET3) $(DSTLIB)
	#cp arp_listen.h $(DSTINC)
$.o:%.c
	@-astyle --style=ansi $< && rm -rf *.orig
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(_OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
#$(TARGET2): $(_OBJS)
#	$(CC) $(SHAREFLAGS) -o $@ $(_OBJS)
#$(TARGET3): $(_OBJS)
#	$(AR) $(ARFLAGS) $@ $(_OBJS)

	


 


clean:
	@$(RM) $(_OBJS) $(TARGET) $(TARGET2) $(TARGET3) $(ORIG_FILES) *.bak *~ 
