.section .text

.global asm_fill32
.type asm_fill32, @function
asm_fill32:
    push %edi
    mov 8(%esp), %edi
    mov 12(%esp), %eax
    mov 16(%esp), %ecx
    cld
    rep stosl
    pop %edi
    ret

.global asm_fill16
.type asm_fill16, @function
asm_fill16:
    push %edi
    mov 8(%esp), %edi
    mov 12(%esp), %eax
    mov 16(%esp), %ecx
    cld
    rep stosw
    pop %edi
    ret
