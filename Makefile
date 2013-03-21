.PHONY: mod run clean all

TARGET=cse536app

all: $(TARGET) mod

$(TARGET): $(TARGET).c
	gcc -g -ggdb $< -o $(TARGET)


clean:
	rm $(TARGET)


run: 
	./$(TARGET)

mod:
	make -C linux-3.2.0/ M=drivers/char/cse536 modules


install: $(TARGET) mod
	-sudo rmmod cse5361
	make -C linux-3.2.0/ M=drivers/char/cse536 modules
	sudo insmod \
		linux-3.2.0/drivers/char/cse536/cse5361.ko debug_enable=1
