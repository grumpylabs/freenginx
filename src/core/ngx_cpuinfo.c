
/*
 * Copyright (C) Igor Sysoev
 */


#include <ngx_config.h>
#include <ngx_core.h>


#if (( __i386__ || __amd64__ ) && ( __GNUC__ || __INTEL_COMPILER ))


static ngx_inline void ngx_cpuid(uint32_t i, uint32_t *buf);


static ngx_inline void
ngx_cpuid(uint32_t i, uint32_t *buf)
{
    uint32_t  eax, ebx, ecx, edx;

    __asm__ (

        "cpuid"

    : "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx) : "a" (i) );

    buf[0] = eax;
    buf[1] = ebx;
    buf[2] = edx;
    buf[3] = ecx;
}


/* auto detect the L2 cache line size of modern and widespread CPUs */

void
ngx_cpuinfo(void)
{
    u_char    *vendor;
    uint32_t   vbuf[5], cpu[4];

    vbuf[0] = 0;
    vbuf[1] = 0;
    vbuf[2] = 0;
    vbuf[3] = 0;
    vbuf[4] = 0;

    ngx_cpuid(0, vbuf);

    vendor = (u_char *) &vbuf[1];

    if (vbuf[0] == 0) {
        return;
    }

    ngx_cpuid(1, cpu);

    if (ngx_strcmp(vendor, "GenuineIntel") == 0) {

        switch (cpu[0] & 0xf00) {

        /* Pentium */
        case 5:
        /* Pentium Pro, II, III */
        case 6:
            ngx_cacheline_size = 32;
            break;

        /*
         * Pentium 4, although its cache line size is 64 bytes,
         * it prefetches up to two cache lines during memory read
         */
        case 15:
            ngx_cacheline_size = 128;
            break;
        }

    } else if (ngx_strcmp(vendor, "AuthenticAMD") == 0) {
        ngx_cacheline_size = 64;
    }
}

#else


void
ngx_cpuinfo(void)
{
}


#endif
