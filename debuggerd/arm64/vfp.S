    .text
    .align 2
    .global crash
    .type crash, %function
crash:
    fmov   d0, XZR
    fmov   d1, 1.0
    fmov   d2, 2.0
    fmov   d3, 3.0
    fmov   d4, 4.0
    fmov   d5, 5.0
    fmov   d6, 6.0
    fmov   d7, 7.0
    fmov   d8, 8.0
    fmov   d9, 9.0
    fmov   d10, 10.0
    fmov   d11, 11.0
    fmov   d12, 12.0
    fmov   d13, 13.0
    fmov   d14, 14.0
    fmov   d15, 15.0
    fmov   d16, 16.0
    fmov   d17, 17.0
    fmov   d18, 18.0
    fmov   d19, 19.0
    fmov   d20, 20.0
    fmov   d21, 21.0
    fmov   d22, 22.0
    fmov   d23, 23.0
    fmov   d24, 24.0
    fmov   d25, 25.0
    fmov   d26, 26.0
    fmov   d27, 27.0
    fmov   d28, 28.0
    fmov   d29, 29.0
    fmov   d30, 30.0
    fmov   d31, 31.0

    mov       x0, xzr
    str       x0, [x0]
    br        x30

