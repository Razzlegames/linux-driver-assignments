.PHONY: mod run clean all udpserver

TARGET=cse536app
DEVICE= /dev/cse5361
LIBS = -pthread

MY_PATH= linux-3.2.0/drivers/char/cse536/
INCLUDE = -I$(MY_PATH)
CFLAGS = -Wall -g -ggdb $(INCLUDE)

CFILES = \
	$(wildcard ./*.c) \

OBJS = \
	$(CFILES:.c=.o)

CDEPS = $(CFILES:.c=.d)
DEPS = $(CDEPS)

MY_LOCAL_SRC_FILES := \
	$(wildcard $(MY_PATH)/*.c) \
	$(wildcard $(MY_PATH)/*.h) \
	$(wildcard ./*.c) \
	$(wildcard ./*.h) \

all: tags $(TARGET) mod udpserver

$(TARGET): $(OBJS)  
	$(CXX) $(CFLAGS) $(LIBS) $(OBJS) -o $(TARGET)

udpserver:
	$(MAKE) -C udpserver_test/

#--------------------------------------------------------
# Rules for building c files
#--------------------------------------------------------
%.o: %.c
	@echo $(notdir $<)
	$(MAKE) tags
	$(CXX) -MMD -MP -MF $*.d $(CFLAGS) -c $< -o $@

clean:
	rm $(TARGET)
	rm $(DEPS)

run: tags $(TARGET) 
	echo $(MY_LOCAL_SRC_FILES)
	./$(TARGET)

mod:
	make -C linux-3.2.0/ M=drivers/char/cse536 modules

install: $(TARGET) mod tags
	-sudo mknod $(DEVICE) c 234 0
	-sudo chown kyle.kyle $(DEVICE)
	-sudo chown kyle2.kyle2 $(DEVICE)
	sudo chmod o=+rw,g=+rw $(DEVICE)
	-sudo rmmod cse5361
	make -C linux-3.2.0/ M=drivers/char/cse536 modules
	sudo insmod \
		linux-3.2.0/drivers/char/cse536/cse5361.ko debug_enable=1

kernel_tags:
	ctags -f kernel_tags -Rn ./

tags: $(MY_LOCAL_SRC_FILES)
	ctags -Rn $(MY_PATH) ./*.c
