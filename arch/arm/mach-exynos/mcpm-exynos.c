/*
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 *		http://www.samsung.com
 *
 * arch/arm/mach-exynos/mcpm-exynos.c
 *
 * Based on arch/arm/mach-vexpress/dcscb.c
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include <linux/arm-cci.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/of_address.h>

#include <asm/cputype.h>
#include <asm/cp15.h>
#include <asm/mcpm.h>

#include "regs-pmu.h"
#include "common.h"

#define EXYNOS5420_CPUS_PER_CLUSTER	4
#define EXYNOS5420_NR_CLUSTERS		2
#define MCPM_BOOT_ADDR_OFFSET		0x1c

/*
 * The common v7_exit_coherency_flush API could not be used because of the
 * Erratum 799270 workaround. This macro is the same as the common one (in
 * arch/arm/include/asm/cacheflush.h) except for the erratum handling.
 */
#define exynos_v7_exit_coherency_flush(level) \
	asm volatile( \
	"stmfd	sp!, {fp, ip}\n\t"\
	"mrc	p15, 0, r0, c1, c0, 0	@ get SCTLR\n\t" \
	"bic	r0, r0, #"__stringify(CR_C)"\n\t" \
	"mcr	p15, 0, r0, c1, c0, 0	@ set SCTLR\n\t" \
	"isb\n\t"\
	"bl	v7_flush_dcache_"__stringify(level)"\n\t" \
	"clrex\n\t"\
	"mrc	p15, 0, r0, c1, c0, 1	@ get ACTLR\n\t" \
	"bic	r0, r0, #(1 << 6)	@ disable local coherency\n\t" \
	/* Dummy Load of a device register to avoid Erratum 799270 */ \
	"ldr	r4, [%0]\n\t" \
	"and	r4, r4, #0\n\t" \
	"orr	r0, r0, r4\n\t" \
	"mcr	p15, 0, r0, c1, c0, 1	@ set ACTLR\n\t" \
	"isb\n\t" \
	"dsb\n\t" \
	"ldmfd	sp!, {fp, ip}" \
	: \
	: "Ir" (S5P_INFORM0) \
	: "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", \
	  "r9", "r10", "lr", "memory")

/*
 * We can't use regular spinlocks. In the switcher case, it is possible
 * for an outbound CPU to call power_down() after its inbound counterpart
 * is already live using the same logical CPU number which trips lockdep
 * debugging.
 */
static arch_spinlock_t exynos_mcpm_lock = __ARCH_SPIN_LOCK_UNLOCKED;
static int
cpu_use_count[EXYNOS5420_CPUS_PER_CLUSTER][EXYNOS5420_NR_CLUSTERS];

#define exynos_cluster_usecnt(cluster) \
	(cpu_use_count[0][cluster] +   \
	 cpu_use_count[1][cluster] +   \
	 cpu_use_count[2][cluster] +   \
	 cpu_use_count[3][cluster])

#define exynos_cluster_unused(cluster) !exynos_cluster_usecnt(cluster)

static int exynos_cluster_power_control(unsigned int cluster, int enable)
{
	unsigned int tries = 100;
	unsigned int val;

	if (enable) {
		exynos_cluster_power_up(cluster);
		val = S5P_CORE_LOCAL_PWR_EN;
	} else {
		exynos_cluster_power_down(cluster);
		val = 0;
	}

	/* Wait until cluster power control is applied */
	while (tries--) {
		if (exynos_cluster_power_state(cluster) == val)
			return 0;

		cpu_relax();
	}
	pr_debug("timed out waiting for cluster %u to power %s\n", cluster,
		enable ? "on" : "off");

	return -ETIMEDOUT;
}

static int exynos_power_up(unsigned int cpu, unsigned int cluster)
{
	unsigned int cpunr = cpu + (cluster * EXYNOS5420_CPUS_PER_CLUSTER);
	int err = 0;

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	if (cpu >= EXYNOS5420_CPUS_PER_CLUSTER ||
		cluster >= EXYNOS5420_NR_CLUSTERS)
		return -EINVAL;

	/*
	 * Since this is called with IRQs enabled, and no arch_spin_lock_irq
	 * variant exists, we need to disable IRQs manually here.
	 */
	local_irq_disable();
	arch_spin_lock(&exynos_mcpm_lock);

	cpu_use_count[cpu][cluster]++;
	if (cpu_use_count[cpu][cluster] == 1) {
		bool was_cluster_down =
			(exynos_cluster_usecnt(cluster) == 1);

		/*
		 * Turn on the cluster (L2/COMMON) and then power on the
		 * cores.
		 */
		if (was_cluster_down)
			err = exynos_cluster_power_control(cluster, 1);

		if (!err)
			exynos_cpu_power_up(cpunr);
		else
			exynos_cluster_power_control(cluster, 0);
	} else if (cpu_use_count[cpu][cluster] != 2) {
		/*
		 * The only possible values are:
		 * 0 = CPU down
		 * 1 = CPU (still) up
		 * 2 = CPU requested to be up before it had a chance
		 *     to actually make itself down.
		 * Any other value is a bug.
		 */
		BUG();
	}

	arch_spin_unlock(&exynos_mcpm_lock);
	local_irq_enable();

	return err;
}

/*
 * NOTE: This function requires the stack data to be visible through power down
 * and can only be executed on processors like A15 and A7 that hit the cache
 * with the C bit clear in the SCTLR register.
 */
static void exynos_power_down(void)
{
	unsigned int mpidr, cpu, cluster;
	bool last_man = false, skip_wfi = false;
	unsigned int cpunr;

	mpidr = read_cpuid_mpidr();
	cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);
	cpunr =  cpu + (cluster * EXYNOS5420_CPUS_PER_CLUSTER);

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	BUG_ON(cpu >= EXYNOS5420_CPUS_PER_CLUSTER ||
			cluster >= EXYNOS5420_NR_CLUSTERS);

	__mcpm_cpu_going_down(cpu, cluster);

	arch_spin_lock(&exynos_mcpm_lock);
	BUG_ON(__mcpm_cluster_state(cluster) != CLUSTER_UP);
	cpu_use_count[cpu][cluster]--;
	if (cpu_use_count[cpu][cluster] == 0) {
		exynos_cpu_power_down(cpunr);

		if (exynos_cluster_unused(cluster))
			/* TODO: Turn off the cluster here to save power. */
			last_man = true;
	} else if (cpu_use_count[cpu][cluster] == 1) {
		/*
		 * A power_up request went ahead of us.
		 * Even if we do not want to shut this CPU down,
		 * the caller expects a certain state as if the WFI
		 * was aborted.  So let's continue with cache cleaning.
		 */
		skip_wfi = true;
	} else {
		BUG();
	}

	if (last_man && __mcpm_outbound_enter_critical(cpu, cluster)) {
		arch_spin_unlock(&exynos_mcpm_lock);

		if (read_cpuid_part_number() == ARM_CPU_PART_CORTEX_A15) {
			/*
			 * On the Cortex-A15 we need to disable
			 * L2 prefetching before flushing the cache.
			 */
			asm volatile(
			"mcr	p15, 1, %0, c15, c0, 3\n\t"
			"isb\n\t"
			"dsb"
			: : "r" (0x400));
		}

		/* Flush all cache levels for this cluster. */
		exynos_v7_exit_coherency_flush(all);

		/*
		 * Disable cluster-level coherency by masking
		 * incoming snoops and DVM messages:
		 */
		cci_disable_port_by_cpu(mpidr);

		__mcpm_outbound_leave_critical(cluster, CLUSTER_DOWN);
	} else {
		arch_spin_unlock(&exynos_mcpm_lock);

		/* Disable and flush the local CPU cache. */
		exynos_v7_exit_coherency_flush(louis);
	}

	__mcpm_cpu_down(cpu, cluster);

	/* Now we are prepared for power-down, do it: */
	if (!skip_wfi)
		wfi();

	/* Not dead at this point?  Let our caller cope. */
}

static int exynos_wait_for_powerdown(unsigned int cpu, unsigned int cluster)
{
	unsigned int tries = 100;
	unsigned int cpunr = cpu + (cluster * EXYNOS5420_CPUS_PER_CLUSTER);

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	BUG_ON(cpu >= EXYNOS5420_CPUS_PER_CLUSTER ||
			cluster >= EXYNOS5420_NR_CLUSTERS);

	/* Wait for the core state to be OFF */
	while (tries--) {
		if (ACCESS_ONCE(cpu_use_count[cpu][cluster]) == 0) {
			if ((exynos_cpu_power_state(cpunr) == 0))
				return 0; /* success: the CPU is halted */
		}

		/* Otherwise, wait and retry: */
		msleep(1);
	}

	return -ETIMEDOUT; /* timeout */
}

static const struct mcpm_platform_ops exynos_power_ops = {
	.power_up		= exynos_power_up,
	.power_down		= exynos_power_down,
	.wait_for_powerdown	= exynos_wait_for_powerdown,
};

static void __init exynos_mcpm_usage_count_init(void)
{
	unsigned int mpidr, cpu, cluster;

	mpidr = read_cpuid_mpidr();
	cpu = MPIDR_AFFINITY_LEVEL(mpidr, 0);
	cluster = MPIDR_AFFINITY_LEVEL(mpidr, 1);

	pr_debug("%s: cpu %u cluster %u\n", __func__, cpu, cluster);
	BUG_ON(cpu >= EXYNOS5420_CPUS_PER_CLUSTER  ||
			cluster >= EXYNOS5420_NR_CLUSTERS);

	cpu_use_count[cpu][cluster] = 1;
}

/*
 * Enable cluster-level coherency, in preparation for turning on the MMU.
 */
static void __naked exynos_pm_power_up_setup(unsigned int affinity_level)
{
	asm volatile ("\n"
	"cmp	r0, #1\n"
	"bxne	lr\n"
	"b	cci_enable_port_for_self");
}

static const struct of_device_id exynos_dt_mcpm_match[] = {
	{ .compatible = "samsung,exynos5420" },
	{ .compatible = "samsung,exynos5800" },
	{},
};

static int __init exynos_mcpm_init(void)
{
	struct device_node *node;
	void __iomem *ns_sram_base_addr;
	int ret;

	node = of_find_matching_node(NULL, exynos_dt_mcpm_match);
	if (!node)
		return -ENODEV;
	of_node_put(node);

	if (!cci_probed())
		return -ENODEV;

	node = of_find_compatible_node(NULL, NULL,
			"samsung,exynos4210-sysram-ns");
	if (!node)
		return -ENODEV;

	ns_sram_base_addr = of_iomap(node, 0);
	of_node_put(node);
	if (!ns_sram_base_addr) {
		pr_err("failed to map non-secure iRAM base address\n");
		return -ENOMEM;
	}

	/*
	 * To increase the stability of KFC reset we need to program
	 * the PMU SPARE3 register
	 */
	__raw_writel(EXYNOS5420_SWRESET_KFC_SEL, S5P_PMU_SPARE3);

	exynos_mcpm_usage_count_init();

	ret = mcpm_platform_register(&exynos_power_ops);
	if (!ret)
		ret = mcpm_sync_init(exynos_pm_power_up_setup);
	if (ret) {
		iounmap(ns_sram_base_addr);
		return ret;
	}

	mcpm_smp_set_ops();

	pr_info("Exynos MCPM support installed\n");

	/*
	 * Future entries into the kernel can now go
	 * through the cluster entry vectors.
	 */
	__raw_writel(virt_to_phys(mcpm_entry_point),
			ns_sram_base_addr + MCPM_BOOT_ADDR_OFFSET);

	iounmap(ns_sram_base_addr);

	return ret;
}

early_initcall(exynos_mcpm_init);
