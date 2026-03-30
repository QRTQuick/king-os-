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

$(BUILD_DIR)/fastfill.o: src/kernel/fastfill.s | $(BUILD_DIR)
	$(CC) $(ASFLAGS) -c $< -o $@

$(BUILD_DIR)/interrupts.o: src/kernel/interrupts.s | $(BUILD_DIR)
	$(CC) $(ASFLAGS) -c $< -o $@

$(KERNEL_BIN): $(BUILD_DIR)/boot.o $(BUILD_DIR)/kernel.o $(BUILD_DIR)/fastfill.o $(BUILD_DIR)/interrupts.o linker.ld
	$(LD) $(LDFLAGS) -o $@ $(BUILD_DIR)/boot.o $(BUILD_DIR)/kernel.o $(BUILD_DIR)/fastfill.o $(BUILD_DIR)/interrupts.o

$(ISO_IMG): $(KERNEL_BIN) boot\ logo.png
	mkdir -p $(ISO_DIR)/boot $(ISO_DIR)/boot/grub
	cp $(KERNEL_BIN) $(ISO_DIR)/boot/kernel.bin
	cp 'boot logo.png' $(ISO_DIR)/boot/grub/boot_logo.png
	grub-mkrescue -o $(ISO_IMG) $(ISO_DIR)

run: $(ISO_IMG)
	qemu-system-i386 -cdrom $(ISO_IMG) -boot d -m 512 -vga std

run-py-gui:
	python3 tools/gui/koroli_desktop_gui.py

build-linux-py-iso:
	sudo bash tools/live_iso/build_koroli_live_iso.sh

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run run-py-gui build-linux-py-iso clean
