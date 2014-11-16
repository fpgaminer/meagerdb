# Inspired by (https://github.com/mbcrawfo/GenericMakefile)

BIN_NAME=libmeagerdb.a
C_SOURCES = \
	src/meagerdb.c \
	src/keyvalue.c \
	src/ciphers.c


SRC_EXT = c
SRC_PATH = src
COMPILE_FLAGS = -std=c99 -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wmissing-prototypes
#COMPILE_FLAGS = -Wconversion -Wsign-conversion
RCOMPILE_FLAGS = -O3
DCOMPILE_FLAGS = -g
INCLUDES = -I$(SRC_PATH) -Ideps/strong-arm/include -Iinclude


# Target
TARGET ?= linux

ifeq ($(TARGET),linux)
	CC = gcc
	OBJCOPY = objcopy
	AR = ar
	RBUILD_PATH = build/linux/release
	DBUILD_PATH = build/linux/debug
else ifeq ($(TARGET),cortex-m4)
	# ARM Cortex M4 (e.g. STM32F4)
	CC = arm-none-eabi-gcc
	OBJCOPY = arm-none-eabi-objcopy
	AR = arm-none-eabi-ar

	COMPILE_FLAGS += -mthumb -mcpu=cortex-m4
	#COMPILE_FLAGS += -mlittle-endian -mthumb -mcpu=cortex-m4 -mthumb-interwork
	#COMPILE_FLAGS += -mfloat-abi=hard -mfpu=fpv4-sp-d16
	COMPILE_FLAGS += -mfloat-abi=soft
	# TODO: hard float was causing an exception; see what's up.
	RBUILD_PATH = build/cortex-m4/release
	DBUILD_PATH = build/cortex-m4/debug
else
$(error "TARGET must be set, e.g. make TARGET=linux")
endif


# Verbose option, to output compile and link commands
export V = false
export CMD_PREFIX = @
ifeq ($(V),true)
	CMD_PREFIX =
endif

# Combine compiler and linker flags
RCCFLAGS = $(CCFLAGS) $(COMPILE_FLAGS) $(RCOMPILE_FLAGS)
RLDFLAGS = $(LDFLAGS) $(LINK_FLAGS) $(RLINK_FLAGS)
DCCFLAGS = $(CCFLAGS) $(COMPILE_FLAGS) $(DCOMPILE_FLAGS)
DLDFLAGS = $(LDFLAGS) $(LINK_FLAGS) $(DLINK_FLAGS)

# Set the object file names, with the source directory stripped
# from the path, and the build path prepended in its place
DOBJECTS := $(C_SOURCES:%.c=$(DBUILD_PATH)/%.o)
DOBJECTS := $(DOBJECTS:%.s=$(DBUILD_PATH)/%.o)
ROBJECTS := $(C_SOURCES:%.c=$(RBUILD_PATH)/%.o)
ROBJECTS := $(ROBJECTS:%.s=$(RBUILD_PATH)/%.o)

# Set the dependency files that will be used to add header dependencies
DDEPS = $(DOBJECTS:.o=.d)
RDEPS = $(ROBJECTS:.o=.d)

# Main rule
all: dirs $(DBUILD_PATH)/$(BIN_NAME) $(RBUILD_PATH)/$(BIN_NAME)

# Create the directories used in the build
.PHONY: dirs
dirs:
	@echo "Creating directories"
	@mkdir -p $(dir $(DOBJECTS))
	@mkdir -p $(dir $(ROBJECTS))

# Link the executable
$(DBUILD_PATH)/$(BIN_NAME): $(DOBJECTS)
	@echo "Creating library: $@"
	$(CMD_PREFIX)$(AR) rcs $@ $(DOBJECTS)

$(RBUILD_PATH)/$(BIN_NAME): $(ROBJECTS)
	@echo "Creating library: $@"
	$(CMD_PREFIX)$(AR) rcs $@ $(ROBJECTS)

# Add dependency files, if they exist
-include $(DDEPS)
-include $(RDEPS)

# Source file rules
# After the first compilation they will be joined with the rules from the
# dependency files to provide header dependencies
$(DBUILD_PATH)/%.o: %.c
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(DBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(DCCFLAGS) $(INCLUDES) -I$(DBUILD_PATH) -MP -MMD -c $< -o $@

$(DBUILD_PATH)/%.o: %.s
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(DBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(DCCFLAGS) $(INCLUDES) -I$(DBUILD_PATH) -MP -MMD -c $< -o $@

$(RBUILD_PATH)/%.o: %.c
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(RBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(RCCFLAGS) $(INCLUDES) -I$(RBUILD_PATH) -MP -MMD -c $< -o $@

$(RBUILD_PATH)/%.o: %.s
	@echo "Compiling: $< -> $@"
	$(eval BUILD_PATH := $(RBUILD_PATH))
	$(CMD_PREFIX)$(CC) $(RCCFLAGS) $(INCLUDES) -I$(RBUILD_PATH) -MP -MMD -c $< -o $@


.PHONE: clean
clean:
	@echo "Deleting directories"
	@$(RM) -r build
