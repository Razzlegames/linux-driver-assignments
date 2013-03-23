.PHONY: mod run clean all

TARGET=cse536app

all: $(TARGET) mod

$(TARGET): $(TARGET).c tags
	gcc -g -ggdb $< -o $(TARGET)


clean:
	rm $(TARGET)


run: $(TARGET) tags
	./$(TARGET)

mod:
	make -C linux-3.2.0/ M=drivers/char/cse536 modules

install: $(TARGET) mod tags
	-sudo rmmod cse5361
	make -C linux-3.2.0/ M=drivers/char/cse536 modules
	sudo insmod \
		linux-3.2.0/drivers/char/cse536/cse5361.ko debug_enable=1

kernel_tags:
	ctags -f kernel_tags -Rn ./

tags:
	ctags -Rn linux-3.2.0/drivers/char/cse536/ ./*.c
