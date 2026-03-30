.set MBALIGN,  1<<0
.set MEMINFO,  1<<1
.set FLAGS,    MBALIGN | MEMINFO
.set MAGIC,    0x1BADB002
.set CHECKSUM, -(MAGIC + FLAGS)

.section .multiboot, "a"
.align 4
.long MAGIC
.long FLAGS
.long CHECKSUM

.section .text
.global _start
.extern kmain

_start:
    cli
    mov $stack_top, %esp
    push %ebx      /* multiboot info address */
    push %eax      /* multiboot magic */
    call kmain

halt:
    hlt
    jmp halt

.section .bss
.align 16
stack_bottom:
.skip 16384
stack_top:
