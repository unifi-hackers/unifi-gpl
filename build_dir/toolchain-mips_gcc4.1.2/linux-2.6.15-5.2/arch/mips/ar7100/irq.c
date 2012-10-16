/*
 * General Interrupt handling for AR7100 soc
 */
#include <linux/config.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/pm.h>
#include <linux/delay.h>
#include <linux/reboot.h>

#include <asm/irq.h>
#include <asm/mipsregs.h>
#include <asm/gdb-stub.h>

#include "ar7100.h"
#include <asm/irq_cpu.h>

/*
 * dummy irqaction, so that interrupt controller cascading can work. Basically
 * when one IC is connected to another, this will be used to enable to Parent
 * IC's irq line to which the child IC is connected
 */
static struct irqaction cascade  =
    {no_action, SA_INTERRUPT, { { 0, } }, "cascade", NULL, NULL};


static void ar7100_dispatch_misc_intr(struct pt_regs *regs);
static void ar7100_dispatch_pci_intr(struct pt_regs *regs);
static void ar7100_dispatch_gpio_intr(struct pt_regs *regs);
static void ar7100_misc_irq_init(int irq_base);
extern asmlinkage void ar7100_interrupt_receive(void);

void __init arch_init_irq(void)
{
    set_except_vector(0, ar7100_interrupt_receive);

    /*
     * initialize our interrupt controllers
     */
    mips_cpu_irq_init(AR7100_CPU_IRQ_BASE);
    ar7100_misc_irq_init(AR7100_MISC_IRQ_BASE);
    ar7100_gpio_irq_init(AR7100_GPIO_IRQ_BASE);
#ifdef CONFIG_PCI
    ar7100_pci_irq_init(AR7100_PCI_IRQ_BASE);
#endif

    /*
     * enable cascades
     */
    setup_irq(AR7100_CPU_IRQ_MISC,  &cascade);
    setup_irq(AR7100_MISC_IRQ_GPIO, &cascade);
#ifdef CONFIG_PCI
    setup_irq(AR7100_CPU_IRQ_PCI,   &cascade);
#endif
}

static void
ar7100_dispatch_misc_intr(struct pt_regs *regs)
{
    int pending;
   
    pending = ar7100_reg_rd(AR7100_MISC_INT_STATUS) &
              ar7100_reg_rd(AR7100_MISC_INT_MASK);

    if (pending & MIMR_UART)
        do_IRQ(AR7100_MISC_IRQ_UART, regs);

    else if (pending & MIMR_DMA)
        do_IRQ(AR7100_MISC_IRQ_DMA, regs);

    else if (pending & MIMR_PERF_COUNTER)
        do_IRQ(AR7100_MISC_IRQ_PERF_COUNTER, regs);

    else if (pending & MIMR_TIMER)
        do_IRQ(AR7100_MISC_IRQ_TIMER, regs);

    else if (pending & MIMR_OHCI_USB)
        do_IRQ(AR7100_MISC_IRQ_USB_OHCI, regs);

    else if (pending & MIMR_ERROR)
        do_IRQ(AR7100_MISC_IRQ_ERROR, regs);

    else if (pending & MIMR_GPIO)
        ar7100_dispatch_gpio_intr(regs);

    else if (pending & MIMR_WATCHDOG)
        do_IRQ(AR7100_MISC_IRQ_WATCHDOG, regs);
}
#ifndef CONFIG_AR9100
static void
ar7100_dispatch_pci_intr(struct pt_regs *regs)
{
    int pending;
   
    pending  = ar7100_reg_rd(AR7100_PCI_INT_STATUS) &
               ar7100_reg_rd(AR7100_PCI_INT_MASK);

    if (pending & PISR_DEV0)
        do_IRQ(AR7100_PCI_IRQ_DEV0, regs);

    else if (pending & PISR_DEV1)
        do_IRQ(AR7100_PCI_IRQ_DEV1, regs);

    else if (pending & PISR_DEV2)
        do_IRQ(AR7100_PCI_IRQ_DEV2, regs);
}
#endif
static void
ar7100_dispatch_gpio_intr(struct pt_regs *regs)
{
    int pending, i;

    pending = ar7100_reg_rd(AR7100_GPIO_INT_PENDING) &
              ar7100_reg_rd(AR7100_GPIO_INT_MASK);

    for(i = 0; i < AR7100_GPIO_COUNT; i++) {
        if (pending & (1 << i))
            do_IRQ(AR7100_GPIO_IRQn(i), regs);
    }
}

/*
 * Dispatch interrupts. 
 * XXX: This currently does not prioritize except in calling order. Eventually
 * there should perhaps be a static map which defines, the IPs to be masked for
 * a given IP.
 */
void
ar7100_irq_dispatch(struct pt_regs *regs)
{
	int pending = read_c0_status() & read_c0_cause();

	if (pending & CAUSEF_IP7) 
        do_IRQ(AR7100_CPU_IRQ_TIMER, regs);
#ifndef CONFIG_AR9100
    else if (pending & CAUSEF_IP2)
        ar7100_dispatch_pci_intr(regs);
#else
    else if (pending & CAUSEF_IP2)
        do_IRQ(AR7100_CPU_IRQ_WMAC, regs);
#endif

    else if (pending & CAUSEF_IP4) 
        do_IRQ(AR7100_CPU_IRQ_GE0, regs);

    else if (pending & CAUSEF_IP5) 
        do_IRQ(AR7100_CPU_IRQ_GE1, regs);

    else if (pending & CAUSEF_IP3) 
        do_IRQ(AR7100_CPU_IRQ_USB, regs);

    else if (pending & CAUSEF_IP6) 
        ar7100_dispatch_misc_intr(regs);

    /*
     * Some PCI devices are write to clear. These writes are posted and might
     * require a flush (r8169.c e.g.). Its unclear what will have more 
     * performance impact - flush after every interrupt or taking a few
     * "spurious" interrupts. For now, its the latter.
     */
    /*else 
        printk("spurious IRQ pending: 0x%x\n", pending);*/
}

static void
ar7100_misc_irq_enable(unsigned int irq)
{
    ar7100_reg_rmw_set(AR7100_MISC_INT_MASK, 
                       (1 << (irq - AR7100_MISC_IRQ_BASE)));
}

static void
ar7100_misc_irq_disable(unsigned int irq)
{
    ar7100_reg_rmw_clear(AR7100_MISC_INT_MASK, 
                       (1 << (irq - AR7100_MISC_IRQ_BASE)));
}
static unsigned int
ar7100_misc_irq_startup(unsigned int irq)
{
	ar7100_misc_irq_enable(irq);
	return 0;
}

static void
ar7100_misc_irq_shutdown(unsigned int irq)
{
	ar7100_misc_irq_disable(irq);
}

static void
ar7100_misc_irq_ack(unsigned int irq)
{
	ar7100_misc_irq_disable(irq);
}

static void
ar7100_misc_irq_end(unsigned int irq)
{
	if (!(irq_desc[irq].status & (IRQ_DISABLED | IRQ_INPROGRESS)))
		ar7100_misc_irq_enable(irq);
}

static void
ar7100_misc_irq_set_affinity(unsigned int irq, unsigned long mask)
{
	/* 
     * Only 1 CPU; ignore affinity request 
     */
}

struct hw_interrupt_type ar7100_misc_irq_controller = {
	"AR7100 MISC",
	ar7100_misc_irq_startup,
	ar7100_misc_irq_shutdown,
	ar7100_misc_irq_enable,
	ar7100_misc_irq_disable,
	ar7100_misc_irq_ack,
	ar7100_misc_irq_end,
	ar7100_misc_irq_set_affinity,
};

/*
 * Determine interrupt source among interrupts that use IP6
 */
static void
ar7100_misc_irq_init(int irq_base)
{
	int i;

	for (i = irq_base; i < irq_base + AR7100_MISC_IRQ_COUNT; i++) {
		irq_desc[i].status = IRQ_DISABLED;
		irq_desc[i].action = NULL;
		irq_desc[i].depth = 1;
		irq_desc[i].handler = &ar7100_misc_irq_controller;
	}
}

