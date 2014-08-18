PROJ_NAME=libmeagerdb
OBJDIR = build

SRCS = src/meagerdb.c


CFLAGS = -g -Wall -Wextra -Wno-missing-braces -Wno-missing-field-initializers -std=c99
#CFLAGS += -O3 -funroll-loops

ifeq ($(TARGET),linux)
	CC=gcc
	OBJCOPY=objcopy
	AR=ar
else ifeq ($(TARGET),cygwin_mingw)
	CC=i686-pc-mingw32-gcc
	OBJCOPY=i686-pc-mingw32-objcopy
	AR=i686-pc-mingw32-ar
else ifeq ($(TARGET),stm32f4)
	# ARM Cortex M4 (STM32F4)
	CC=arm-none-eabi-gcc
	OBJCOPY=arm-none-eabi-objcopy
	AR=arm-none-eabi-ar

	CFLAGS += -mthumb -mcpu=cortex-m4
	#CFLAGS += -mlittle-endian -mthumb -mcpu=cortex-m4 -mthumb-interwork
	#CFLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
	CFLAGS += -mfloat-abi=soft
	# TODO: hard float was causing an exception; see what's up.
	CFLAGS += -DTARGET_STM32F4
else
$(error "TARGET must be set, e.g. make TARGET=stm32f4")
endif


CFLAGS += -Iinclude -Ideps/strong-arm/include


OBJS := $(SRCS:.c=.o)
OBJS := $(OBJS:.s=.o)
OBJS := $(patsubst src%.o,build%.o, $(OBJS))


all: $(OBJDIR)/$(PROJ_NAME).a

$(OBJDIR)/%.a: $(OBJS)
	$(AR) rcs $@ $^

$(OBJDIR)/%.o: src/%.c
	mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) -o $@ $^

$(OBJDIR)/%.o: src/%.s
	$(CC) -c $(CFLAGS) -o $@ $^

$(OBJDIR):
	mkdir -p $@

clean:
	rm -f $(OBJDIR)/$(PROJ_NAME).a
	find $(OBJDIR) -type f -name '*.o' -print0 | xargs -0 -r rm


# Dependdencies
$(OBJDIR)/$(PROJ_NAME).elf: $(OBJS) | $(OBJDIR)
