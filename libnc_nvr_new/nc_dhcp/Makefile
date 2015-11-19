INST=../../inst/

AR=$(CROSS_COMPILE)ar
CC=$(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip

SHAREFLAGS = -fPIC -shared
ARFLAGS=cr
CFLAGS=$(CROSS_EXTRA_CFLAGS) -DDEBUG -DLINUX -Os -ffunction-sections -fdata-sections -fno-exceptions -Wall  \
			-I.
#CFLAGS= -DDEBUG -DLINUX -Os -ffunction-sections -fdata-sections -fno-exceptions -Wall  \
#		-I.

LDFLAGS=-lm -lpthread -lrt -Wl,--gc-sections 

TARGET1:=libncdhcp.so
TARGET2:=libncdhcp.a

COMM_SRC=$(shell find . -name \*.c)
COMM_OBJS=$(COMM_SRC:%.c=%.o)
OBJS=$(COMM_OBJS)


all: $(TARGET2) $(TARGET1)
	$(STRIP) $(TARGET1)
	#-@astyle --style=allman $<
%.o:%.c	
	$(CC) -o $@ -c $< $(CFLAGS)
$(TARGET2): $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	cp $(TARGET2) $(INST)lib
$(TARGET1): $(OBJS)
	$(CC) $(SHAREFLAGS) -o $@ $^ 
	cp $(TARGET1) $(INST)lib
	cp nc_dhcp.h $(INST)include

clean:
	rm -rf $(OBJS) $(TARGET1) $(TARGET2)
	rm -rf $(INST)lib/$(TARGET1) $(INST)lib/$(TARGET2) $(TARGET1)include/nc_dhcp.h
.PHONY:clean
