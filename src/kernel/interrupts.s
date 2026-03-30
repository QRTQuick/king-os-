.section .text

.extern irq0_handler
.extern irq1_handler

.global load_idt
.type load_idt, @function
load_idt:
    mov 4(%esp), %eax
    lidt (%eax)
    ret

.global enable_interrupts
.type enable_interrupts, @function
enable_interrupts:
    sti
    ret

.global disable_interrupts
.type disable_interrupts, @function
disable_interrupts:
    cli
    ret

.global hlt_cpu
.type hlt_cpu, @function
hlt_cpu:
    hlt
    ret

.global irq0_stub
.type irq0_stub, @function
irq0_stub:
    pusha
    call irq0_handler
    popa
    iret

.global irq1_stub
.type irq1_stub, @function
irq1_stub:
    pusha
    call irq1_handler
    popa
    iret

.global irq_ignore_stub
.type irq_ignore_stub, @function
irq_ignore_stub:
    iret
