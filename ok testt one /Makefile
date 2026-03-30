CC := gcc
LD := ld

CFLAGS := -m32 -ffreestanding -fno-stack-protector -fno-pic -nostdlib -Wall -Wextra -O2
ASFLAGS := -m32
LDFLAGS := -m elf_i386 -T linker.ld -nostdlib

BUILD_DIR := build
ISO_DIR := iso
KERNEL_BIN := $(BUILD_DIR)/kernel.bin
ISO_IMG := $(BUILD_DIR)/koroli-os.iso

all: $(ISO_IMG)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/boot.o: src/boot/boot.s | $(BUILD_DIR)
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/kernel.o: src/kernel/kernel.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(KERNEL_BIN): $(BUILD_DIR)/boot.o $(BUILD_DIR)/kernel.o linker.ld
	$(LD) $(LDFLAGS) -o $@ $(BUILD_DIR)/boot.o $(BUILD_DIR)/kernel.o

$(ISO_IMG): $(KERNEL_BIN)
	mkdir -p $(ISO_DIR)/boot
	cp $(KERNEL_BIN) $(ISO_DIR)/boot/kernel.bin
	grub-mkrescue -o $(ISO_IMG) $(ISO_DIR)

run: $(ISO_IMG)
	qemu-system-i386 -cdrom $(ISO_IMG)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run clean
