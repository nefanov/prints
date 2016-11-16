/*
This function sets WP bit to zero to allow writing into a memory pages of x86 Linux Kernel;
Code is SMP-unsafe;
*/

static inline unsigned long native_pax_open_kernel(void)
{
    unsigned long cr0;

    preempt_disable();
    barrier();
    cr0 = read_cr0() ^ X86_CR0_WP;
    BUG_ON(unlikely(cr0 & X86_CR0_WP));
    write_cr0(cr0);
    return cr0 ^ X86_CR0_WP;
}

/*
This function restores WP bit to protect x86 Linux Kernel pages from writing;
Code is SMP-unsafe;
*/

static inline unsigned long native_pax_close_kernel(void)
{
    unsigned long cr0;

    cr0 = read_cr0() ^ X86_CR0_WP;
    BUG_ON(unlikely(!(cr0 & X86_CR0_WP)));
    write_cr0(cr0);
    barrier();
    preempt_enable_no_resched();
    return cr0 ^ X86_CR0_WP;
}
