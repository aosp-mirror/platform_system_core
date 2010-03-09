    .text
    .align 2
    .global crash
    .type crash, %function
crash:
    fconstd   d0, #0
    fconstd   d1, #1
    fconstd   d2, #2
    fconstd   d3, #3
    fconstd   d4, #4
    fconstd   d5, #5
    fconstd   d6, #6
    fconstd   d7, #7
    fconstd   d8, #8
    fconstd   d9, #9
    fconstd   d10, #10
    fconstd   d11, #11
    fconstd   d12, #12
    fconstd   d13, #13
    fconstd   d14, #14
    fconstd   d15, #15
#ifdef WITH_VFP_D32
    fconstd   d16, #16
    fconstd   d17, #17
    fconstd   d18, #18
    fconstd   d19, #19
    fconstd   d20, #20
    fconstd   d21, #21
    fconstd   d22, #22
    fconstd   d23, #23
    fconstd   d24, #24
    fconstd   d25, #25
    fconstd   d26, #26
    fconstd   d27, #27
    fconstd   d28, #28
    fconstd   d29, #29
    fconstd   d30, #30
    fconstd   d31, #31
#endif
    mov       r0, #0
    str       r0, [r0]
    bx        lr

