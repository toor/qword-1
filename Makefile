# Globals and files to compile.
KERNEL    := qword
KERNELELF := $(KERNEL).elf
KERNELHDD := $(KERNEL).hdd
SOURCEDIR := src
RUNDIR    := run

LAI_URL     := https://github.com/qword-os/lai.git
LAI_DIR     := $(SOURCEDIR)/acpi/lai
QLOADER_URL := https://github.com/qloader2/qloader2.git
QLOADER_DIR := qloader2

CFILES    := $(shell find $(SOURCEDIR) -type f -name '*.c')
ASMFILES  := $(shell find $(SOURCEDIR) -type f -name '*.asm')
REALFILES := $(shell find $(SOURCEDIR) -type f -name '*.real')
BINS      := $(REALFILES:.real=.bin)
OBJ       := $(CFILES:.c=.o) $(ASMFILES:.asm=.asm.o)
DEPS      := $(CFILES:.c=.d)

# User options.
DBGOUT = no
DBGSYM = no

PREFIX = $(shell pwd)

CC      = gcc
LD      = $(CC:gcc=ld)
AS      = nasm
QEMU    = qemu-system-x86_64

CFLAGS    = -O2 -pipe -Wall -Wextra
LDFLAGS   = -O2
QEMUFLAGS = -m 2G -enable-kvm -smp 4 -netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no,net=0x123456 -device rtl8139,netdev=mynet0

# Flags for compilation.
BUILD_TIME := $(shell date)

CHARDFLAGS := $(CFLAGS)            \
	-DBUILD_TIME='"$(BUILD_TIME)"' \
	-std=gnu99                     \
	-masm=intel                    \
	-fno-pic                       \
	-mno-sse                       \
	-mno-sse2                      \
	-mno-mmx                       \
	-mno-80387                     \
	-mno-red-zone                  \
	-mcmodel=kernel                \
	-ffreestanding                 \
	-fno-stack-protector           \
	-fno-omit-frame-pointer        \
	-I$(SOURCEDIR)                 \
	-I$(LAI_DIR)/include

ifeq ($(DBGOUT), tty)
CHARDFLAGS := $(CHARDFLAGS) -D_DBGOUT_TTY_
else ifeq ($(DBGOUT), qemu)
CHARDFLAGS := $(CHARDFLAGS) -D_DBGOUT_QEMU_
else ifeq ($(DBGOUT), both)
CHARDFLAGS := $(CHARDFLAGS) -D_DBGOUT_TTY_ -D_DBGOUT_QEMU_
endif

ifeq ($(DBGSYM), yes)
CHARDFLAGS := $(CHARDFLAGS) -g -D_DEBUG_
endif

LDHARDFLAGS := $(LDFLAGS)     \
	-nostdlib                 \
	-no-pie                   \
	-z max-page-size=0x1000   \
	-T $(SOURCEDIR)/linker.ld

QEMUHARDFLAGS := $(QEMUFLAGS) \
	-debugcon stdio           \
	-hda $(KERNELHDD)

.PHONY: symlist all prepare build install uninstall clean run

all: $(LAI_DIR)
ifeq ($(PULLREPOS), true)
	cd $(LAI_DIR)     && git pull
	cd $(QLOADER_DIR) && git pull
else
	true # -- NOT PULLING LAI REPO -- #
endif
	$(MAKE) build

build: $(KERNELELF)

$(LAI_DIR):
	git clone $(LAI_URL) $(LAI_DIR)

$(KERNELELF): $(LAI_DIR) $(BINS) $(OBJ) symlist
	$(LD) $(LDHARDFLAGS) $(OBJ) symlist.o -o $@
	OBJDUMP=$(CC:-gcc:-objdump) ./gensyms.sh
	$(CC) -x c $(CHARDFLAGS) -c symlist.gen -o symlist.o
	$(LD) $(LDHARDFLAGS) $(OBJ) symlist.o -o $@

symlist:
	echo '#include <symlist.h>' > symlist.gen
	echo 'struct symlist_t symlist[] = {{0xffffffffffffffff,""}};' >> symlist.gen
	$(CC) -x c $(CHARDFLAGS) -c symlist.gen -o symlist.o

-include $(DEPS)

%.o: %.c
	$(CC) $(CHARDFLAGS) -MMD -c $< -o $@

%.bin: %.real
	$(AS) $< -f bin -o $@

%.asm.o: %.asm
	$(AS) $< -I$(SOURCEDIR) -f elf64 -o $@

run: $(KERNELHDD)
	$(QEMU) $(QEMUHARDFLAGS)

$(KERNELHDD): $(QLOADER_DIR) $(KERNELELF)
	dd if=/dev/zero bs=1M count=0 seek=64 of=$(KERNELHDD)
	parted -s $(KERNELHDD) mklabel msdos
	parted -s $(KERNELHDD) mkpart primary 1 100%
	echfs-utils -m -p0 $(KERNELHDD) quick-format 32768
	echfs-utils -m -p0 $(KERNELHDD) import $(KERNELELF) $(KERNELELF)
	echfs-utils -m -p0 $(KERNELHDD) import $(RUNDIR)/qloader2.cfg qloader2.cfg
	$(QLOADER_DIR)/qloader2-install $(QLOADER_DIR)/qloader2.bin ${KERNELHDD}

$(QLOADER_DIR):
	git clone $(QLOADER_URL) $(QLOADER_DIR)

install: all
	install -d $(DESTDIR)$(PREFIX)/boot
	install $(KERNELBIN) $(DESTDIR)$(PREFIX)/boot/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/boot/$(KERNELBIN)

clean:
	rm -f symlist.gen symlist.o $(OBJ) $(BINS) $(KERNELELF) $(KERNELHDD) $(DEPS)

distclean: clean
	rm -rf $(LAI_DIR) $(QLOADER_DIR)

format:
	find -not -path "./acpi/lai/*" -type f  -name "*.h" -exec clang-format -style=file -i {} \;
	find -not -path "./acpi/lai/*" -type f  -name "*.c" -exec clang-format -style=file -i {} \;
