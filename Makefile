.PHONY: mod run clean all 

TARGET=cse536app
DEVICE= /dev/cse5361

MY_PATH= linux-3.2.0/drivers/char/cse536/

MY_LOCAL_SRC_FILES := \
	$(wildcard $(MY_PATH)/*.c)

all: $(TARGET) mod

$(TARGET): $(TARGET).c tags
	g++ -Wall -g -ggdb $< -o $(TARGET)


clean:
	rm $(TARGET)

run: $(TARGET) tags
	./$(TARGET)

mod:
	make -C linux-3.2.0/ M=drivers/char/cse536 modules

install: $(TARGET) mod tags
	-sudo mknod $(DEVICE) c 234 0
	sudo chown kyle.kyle $(DEVICE)
	sudo chmod o=+rw,g=+rw $(DEVICE)
	-sudo rmmod cse5361
	make -C linux-3.2.0/ M=drivers/char/cse536 modules
	sudo insmod \
		linux-3.2.0/drivers/char/cse536/cse5361.ko debug_enable=1

kernel_tags:
	ctags -f kernel_tags -Rn ./

tags: $(MY_LOCAL_SRC_FILES)
	ctags -Rn $(MY_PATH) ./*.c
