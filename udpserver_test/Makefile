.PHONY: mod run clean all 

TARGET=udpserver
LIBS = -pthread
MY_PATH= ../linux-3.2.0/drivers/char/cse536/
INCLUDE = -I$(MY_PATH)
CFLAGS = -Wall -g -ggdb $(INCLUDE)

CFILES = \
	$(wildcard *.c) \

export OBJS = \
	$(CFILES:.c=.o)

CDEPS = $(CFILES:.c=.d)
DEPS = $(CDEPS)


MY_LOCAL_SRC_FILES := \
	$(wildcard ./*.c) \
	$(wildcard ./*.h) \

all: $(TARGET) 

$(TARGET): $(OBJS)
	@echo "OBjs are: $(OBJS)"
	$(CXX) $(CFLAGS) $(LIBS) $(OBJS) -o $@

-include $(DEPS)

clean:
	-rm $(TARGET) $(DEPS) $(OBJS)

run: $(TARGET) 
	echo $(MY_LOCAL_SRC_FILES)
	./$(TARGET)

#--------------------------------------------------------
# Rules for building c files
#--------------------------------------------------------
%.o: %.c
	@echo $(notdir $<)
	$(CXX) -MMD -MP -MF $*.d $(CFLAGS) -c $< -o $@



install: $(TARGET) 
