// +build amd64

#define _GNU_SOURCE
#include <stdarg.h>
#include <stdio.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <stdlib.h>
#include <getopt.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <sched.h>
#include <time.h>
#include <cpuid.h>
#include <linux/capability.h>
#include <errno.h>
#include <math.h>

char *proc_stat = "/proc/stat";
FILE *outf;
int *fd_percpu;
struct timeval interval_tv = {1, 0};
struct timespec interval_ts = {1, 0};
unsigned int num_iterations;
unsigned int debug;
unsigned int quiet;
unsigned int shown;
unsigned int units = 1000000;	/* MHz etc */
unsigned int genuine_intel;
unsigned int authentic_amd;
unsigned int hygon_genuine;
unsigned int max_level, max_extended_level;
unsigned int has_invariant_tsc;
unsigned int aperf_mperf_multiplier = 1;
unsigned int summary_only;
double bclk;
double base_hz;
unsigned int has_base_hz;
double tsc_tweak = 1.0;
unsigned int show_pkg_only;
unsigned int show_core_only;
char *output_buffer, *outp;
unsigned long long tsc_hz;
int base_cpu;
double discover_bclk(unsigned int family, unsigned int model);
unsigned int has_hwp;	/* IA32_PM_ENABLE, IA32_HWP_CAPABILITIES */
unsigned int first_counter_read = 1;
int ignore_stdin;

#define MSR_IA32_MPERF 0x000000e7
#define MSR_IA32_APERF 0x000000e8

#define ODD_COUNTERS thread_odd
#define EVEN_COUNTERS thread_even

#define MAX(a, b) ((a) > (b) ? (a) : (b))

#define GET_THREAD(thread_base, thread_no, core_no, node_no, pkg_no)	      \
	((thread_base) +						      \
	 ((pkg_no) *							      \
	  topo.nodes_per_pkg * topo.cores_per_node * topo.threads_per_core) + \
	 ((node_no) * topo.cores_per_node * topo.threads_per_core) +	      \
	 ((core_no) * topo.threads_per_core) +				      \
	 (thread_no))

/*
 * buffer size used by sscanf() for added column names
 * Usually truncated to 7 characters, but also handles 18 columns for raw 64-bit counters
 */
#define	NAME_BYTES 20
#define PATH_BYTES 128

int backwards_count;
char *progname;

#define CPU_SUBSET_MAXCPUS	1024	/* need to use before probe... */
cpu_set_t *cpu_present_set, *cpu_affinity_set, *cpu_subset;
size_t cpu_present_setsize, cpu_affinity_setsize, cpu_subset_size;
#define MAX_ADDED_COUNTERS 8
#define MAX_ADDED_THREAD_COUNTERS 24
#define BITMASK_SIZE 32

#define MAX_CORE_NUM 200
int  output[MAX_CORE_NUM];

struct thread_data {
    struct timeval tv_begin;
    struct timeval tv_end;
    struct timeval tv_delta;
    unsigned long long tsc;
    unsigned long long aperf;
    unsigned long long mperf;
    //unsigned long long c1;
    //unsigned long long  irq_count;
    //unsigned int smi_count;
    unsigned int cpu_id;
    unsigned int apic_id;
    unsigned int x2apic_id;
    unsigned int flags;
#define CPU_IS_FIRST_THREAD_IN_CORE    0x2
#define CPU_IS_FIRST_CORE_IN_PACKAGE    0x4
    unsigned long long counter[MAX_ADDED_THREAD_COUNTERS];
} *thread_even, *thread_odd;

struct cpu_topology {
	int physical_package_id;
	int die_id;
	int logical_cpu_id;
	int physical_node_id;
	int logical_node_id;	/* 0-based count within the package */
	int physical_core_id;
	int thread_id;
	cpu_set_t *put_ids; /* Processing Unit/Thread IDs */
} *cpus;


struct topo_params {
	int num_packages;
	int num_die;
	int num_cpus;
	int num_cores;
	int max_cpu_num;
	int max_node_num;
	int nodes_per_pkg;
	int cores_per_node;
	int threads_per_core;
} topo;

enum counter_scope {SCOPE_CPU, SCOPE_CORE, SCOPE_PACKAGE};
enum counter_type {COUNTER_ITEMS, COUNTER_CYCLES, COUNTER_SECONDS, COUNTER_USEC};
enum counter_format {FORMAT_RAW, FORMAT_DELTA, FORMAT_PERCENT};

struct msr_counter {
    unsigned int msr_num;
    char name[NAME_BYTES];
    char path[PATH_BYTES];
    unsigned int width;
    enum counter_type type;
    enum counter_format format;
    struct msr_counter *next;
    unsigned int flags;
#define	FLAGS_HIDE	(1 << 0)
#define	FLAGS_SHOW	(1 << 1)
#define	SYSFS_PERCPU	(1 << 1)
};

struct sys_counters {
    unsigned int added_thread_counters;
    unsigned int added_core_counters;
    unsigned int added_package_counters;
    struct msr_counter *tp;
    struct msr_counter *cp;
    struct msr_counter *pp;
} sys;

struct timeval tv_even, tv_odd, tv_delta;

int *irq_column_2_cpu;	/* /proc/interrupts column numbers */
int *irqs_per_cpu;		/* indexed by cpu_num */

#define MAX_BIC (sizeof(bic) / sizeof(struct msr_counter))
#define	BIC_USEC	(1ULL << 0)
#define	BIC_TOD		(1ULL << 1)
#define	BIC_Package	(1ULL << 2)
#define	BIC_Node	(1ULL << 3)
#define	BIC_Avg_MHz	(1ULL << 4)
#define	BIC_Busy	(1ULL << 5)
#define	BIC_Bzy_MHz	(1ULL << 6)
#define	BIC_TSC_MHz	(1ULL << 7)
#define	BIC_IRQ		(1ULL << 8)
#define	BIC_SMI		(1ULL << 9)
#define	BIC_sysfs	(1ULL << 10)
#define	BIC_CPU_c1	(1ULL << 11)
#define	BIC_CPU_c3	(1ULL << 12)
#define	BIC_CPU_c6	(1ULL << 13)
#define	BIC_CPU_c7	(1ULL << 14)
#define	BIC_ThreadC	(1ULL << 15)
#define	BIC_CoreTmp	(1ULL << 16)
#define	BIC_CoreCnt	(1ULL << 17)
#define	BIC_PkgTmp	(1ULL << 18)
#define	BIC_GFX_rc6	(1ULL << 19)
#define	BIC_GFXMHz	(1ULL << 20)
#define	BIC_Pkgpc2	(1ULL << 21)
#define	BIC_Pkgpc3	(1ULL << 22)
#define	BIC_Pkgpc6	(1ULL << 23)
#define	BIC_Pkgpc7	(1ULL << 24)
#define	BIC_Pkgpc8	(1ULL << 25)
#define	BIC_Pkgpc9	(1ULL << 26)
#define	BIC_Pkgpc10	(1ULL << 27)
#define BIC_CPU_LPI	(1ULL << 28)
#define BIC_SYS_LPI	(1ULL << 29)
#define	BIC_PkgWatt	(1ULL << 30)
#define	BIC_CorWatt	(1ULL << 31)
#define	BIC_GFXWatt	(1ULL << 32)
#define	BIC_PkgCnt	(1ULL << 33)
#define	BIC_RAMWatt	(1ULL << 34)
#define	BIC_PKG__	(1ULL << 35)
#define	BIC_RAM__	(1ULL << 36)
#define	BIC_Pkg_J	(1ULL << 37)
#define	BIC_Cor_J	(1ULL << 38)
#define	BIC_GFX_J	(1ULL << 39)
#define	BIC_RAM_J	(1ULL << 40)
#define	BIC_Mod_c6	(1ULL << 41)
#define	BIC_Totl_c0	(1ULL << 42)
#define	BIC_Any_c0	(1ULL << 43)
#define	BIC_GFX_c0	(1ULL << 44)
#define	BIC_CPUGFX	(1ULL << 45)
#define	BIC_Core	(1ULL << 46)
#define	BIC_CPU		(1ULL << 47)
#define	BIC_APIC	(1ULL << 48)
#define	BIC_X2APIC	(1ULL << 49)
#define	BIC_Die		(1ULL << 50)

#define BIC_DISABLED_BY_DEFAULT	(BIC_USEC | BIC_TOD | BIC_APIC | BIC_X2APIC)

unsigned long long bic_enabled = (0xFFFFFFFFFFFFFFFFULL & ~BIC_DISABLED_BY_DEFAULT);
unsigned long long bic_present = BIC_USEC | BIC_TOD | BIC_sysfs | BIC_APIC | BIC_X2APIC;

#define DO_BIC(COUNTER_NAME) (bic_enabled & bic_present & COUNTER_NAME)
#define DO_BIC_READ(COUNTER_NAME) (bic_present & COUNTER_NAME)
#define ENABLE_BIC(COUNTER_NAME) (bic_enabled |= COUNTER_NAME)
#define BIC_PRESENT(COUNTER_BIT) (bic_present |= COUNTER_BIT)
#define BIC_NOT_PRESENT(COUNTER_BIT) (bic_present &= ~COUNTER_BIT)

void setup_all_buffers(void);

int cpu_is_not_present(int cpu)
{
	return !CPU_ISSET_S(cpu, cpu_present_setsize, cpu_present_set);
}


int parse_int_file(const char *fmt, ...)
{
    va_list args;
    char path[PATH_MAX];
    FILE *filep;
    int value;

    va_start(args, fmt);
    vsnprintf(path, sizeof(path), fmt, args);
    va_end(args);
    filep = fopen(path, "r");
    if (!filep)
        return 0;
    if (fscanf(filep, "%d", &value) != 1)
        err(1, "%s: failed to parse number from file", path);
    fclose(filep);
    return value;
}

/*
 * cpu_is_first_core_in_package(cpu)
 * return 1 if given CPU is 1st core in package
 */
int cpu_is_first_core_in_package(int cpu)
{
    return cpu == parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_siblings_list", cpu);
}

/*
 * run func(thread, core, package) in topology order
 * skip non-present cpus
 */

int cpu_migrate(int cpu)
{
    CPU_ZERO_S(cpu_affinity_setsize, cpu_affinity_set);
    CPU_SET_S(cpu, cpu_affinity_setsize, cpu_affinity_set);
    if (sched_setaffinity(0, cpu_affinity_setsize, cpu_affinity_set) == -1)
        return -1;
    else
        return 0;
}

int get_msr_fd(int cpu)
{
    char pathname[32];
    int fd;

    fd = fd_percpu[cpu];

    if (fd)
        return fd;

    sprintf(pathname, "/dev/cpu/%d/msr", cpu);
    fd = open(pathname, O_RDONLY);
    if (fd < 0)
        err(-1, "%s open failed, try chown or chmod +r /dev/cpu/*/msr, or run as root", pathname);

    fd_percpu[cpu] = fd;

    return fd;
}

int get_msr(int cpu, off_t offset, unsigned long long *msr)
{
    ssize_t retval;

    retval = pread(get_msr_fd(cpu), msr, sizeof(*msr), offset);

    if (retval != sizeof *msr)
        err(-1, "cpu%d: msr offset 0x%llx read failed", cpu, (unsigned long long)offset);

    return 0;
}

void allocate_counters(struct thread_data **t)
{
    int i;
    int num_cores = topo.cores_per_node * topo.nodes_per_pkg *
                    topo.num_packages;
    int num_threads = topo.threads_per_core * num_cores;

    *t = calloc(num_threads, sizeof(struct thread_data));
    if (*t == NULL)
        goto error;

    for (i = 0; i < num_threads; i++)
        (*t)[i].cpu_id = -1;

    return;
    error:
    err(1, "calloc counters");
}

void init_counter(struct thread_data *thread_base, int cpu_id)
{
    int pkg_id = cpus[cpu_id].physical_package_id;
    int node_id = cpus[cpu_id].logical_node_id;
    int core_id = cpus[cpu_id].physical_core_id;
    int thread_id = cpus[cpu_id].thread_id;
    struct thread_data *t;

    /* Workaround for systems where physical_node_id==-1
     * and logical_node_id==(-1 - topo.num_cpus)
     */
    if (node_id < 0)
        node_id = 0;

    t = GET_THREAD(thread_base, thread_id, core_id, node_id, pkg_id);

    t->cpu_id = cpu_id;
    if (thread_id == 0) {
        t->flags |= CPU_IS_FIRST_THREAD_IN_CORE;
        if (cpu_is_first_core_in_package(cpu_id))
            t->flags |= CPU_IS_FIRST_CORE_IN_PACKAGE;
    }
}


int initialize_counters(int cpu_id)
{
    init_counter(EVEN_COUNTERS, cpu_id);
    init_counter(ODD_COUNTERS, cpu_id);
    return 0;
}

static unsigned long long rdtsc(void)
{
    unsigned int low, high;

    asm volatile("rdtsc" : "=a" (low), "=d" (high));

    return low | ((unsigned long long)high) << 32;
}

/*
 * Open a file, and exit on failure
 */
FILE *fopen_or_die(const char *path, const char *mode)
{
    FILE *filep = fopen(path, mode);

    if (!filep)
        err(1, "%s: open failed", path);
    return filep;
}

void get_apic_id(struct thread_data *t)
{
    unsigned int eax, ebx, ecx, edx;

    if (DO_BIC(BIC_APIC)) {
        eax = ebx = ecx = edx = 0;
        __cpuid(1, eax, ebx, ecx, edx);

        t->apic_id = (ebx >> 24) & 0xff;
    }

    if (!DO_BIC(BIC_X2APIC))
        return;

    if (authentic_amd || hygon_genuine) {
        unsigned int topology_extensions;

        if (max_extended_level < 0x8000001e)
            return;

        eax = ebx = ecx = edx = 0;
        __cpuid(0x80000001, eax, ebx, ecx, edx);
        topology_extensions = ecx & (1 << 22);

        if (topology_extensions == 0)
            return;

        eax = ebx = ecx = edx = 0;
        __cpuid(0x8000001e, eax, ebx, ecx, edx);

        t->x2apic_id = eax;
        return;
    }

    if (!genuine_intel)
        return;

    if (max_level < 0xb)
        return;

    ecx = 0;
    __cpuid(0xb, eax, ebx, ecx, edx);
    t->x2apic_id = edx;

    if (debug && (t->apic_id != (t->x2apic_id & 0xff)))
        fprintf(outf, "cpu%d: BIOS BUG: apic 0x%x x2apic 0x%x\n",
                t->cpu_id, t->apic_id, t->x2apic_id);
}


int get_counters(struct thread_data *t)
{
    int cpu = t->cpu_id;
    //unsigned long long msr;
    int aperf_mperf_retry_count = 0;
    //struct msr_counter *mp;

    if (cpu_migrate(cpu)) {
        fprintf(outf, "Could not migrate to CPU %d\n", cpu);
        return -1;
    }

    gettimeofday(&t->tv_begin, (struct timezone *)NULL);

    if (first_counter_read)
        get_apic_id(t);
    retry:
    t->tsc = rdtsc();	/* we are running on local CPU of interest */

    //if (DO_BIC(BIC_Avg_MHz) || DO_BIC(BIC_Busy) || DO_BIC(BIC_Bzy_MHz)){
    if (1){
        unsigned long long tsc_before, tsc_between, tsc_after, aperf_time, mperf_time;

        /*
         * The TSC, APERF and MPERF must be read together for
         * APERF/MPERF and MPERF/TSC to give accurate results.
         *
         * Unfortunately, APERF and MPERF are read by
         * individual system call, so delays may occur
         * between them.  If the time to read them
         * varies by a large amount, we re-read them.
         */

        /*
         * This initial dummy APERF read has been seen to
         * reduce jitter in the subsequent reads.
         */

        if (get_msr(cpu, MSR_IA32_APERF, &t->aperf))
            return -3;

        t->tsc = rdtsc();	/* re-read close to APERF */

        tsc_before = t->tsc;

        if (get_msr(cpu, MSR_IA32_APERF, &t->aperf))
            return -3;

        tsc_between = rdtsc();

        if (get_msr(cpu, MSR_IA32_MPERF, &t->mperf))
            return -4;

        tsc_after = rdtsc();

        aperf_time = tsc_between - tsc_before;
        mperf_time = tsc_after - tsc_between;

        /*
         * If the system call latency to read APERF and MPERF
         * differ by more than 2x, then try again.
         */
        if ((aperf_time > (2 * mperf_time)) || (mperf_time > (2 * aperf_time))) {
            aperf_mperf_retry_count++;
            if (aperf_mperf_retry_count < 5)
                goto retry;
            else
                warnx("cpu%d jitter %lld %lld",
                      cpu, aperf_time, mperf_time);
        }
        aperf_mperf_retry_count = 0;

        t->aperf = t->aperf * aperf_mperf_multiplier;
        t->mperf = t->mperf * aperf_mperf_multiplier;
    }
    //done:
    gettimeofday(&t->tv_end, (struct timezone *)NULL);

    return 0;
}

int for_all_cpus(int (func)(struct thread_data *),
                 struct thread_data *thread_base)
{
    int retval, pkg_no, core_no, thread_no, node_no;

    for (pkg_no = 0; pkg_no < topo.num_packages; ++pkg_no) {
        for (node_no = 0; node_no < topo.nodes_per_pkg; node_no++) {
            for (core_no = 0; core_no < topo.cores_per_node; ++core_no) {
                for (thread_no = 0; thread_no <
                                    topo.threads_per_core; ++thread_no) {
                    struct thread_data *t;

                    t = GET_THREAD(thread_base, thread_no,
                                   core_no, node_no,
                                   pkg_no);

                    if (cpu_is_not_present(t->cpu_id))
                        continue;

                    retval = func(t);
                    if (retval)
                        return retval;
                }
            }
        }
    }
    return 0;
}

/*
 * run func(thread, core, package) in topology order
 * skip non-present cpus
 */

int for_all_cpus_2(int (func)(struct thread_data *, struct thread_data *), struct thread_data *thread_base,
                   struct thread_data *thread_base2)
{
    int retval, pkg_no, node_no, core_no, thread_no;

    for (pkg_no = 0; pkg_no < topo.num_packages; ++pkg_no) {
        for (node_no = 0; node_no < topo.nodes_per_pkg; ++node_no) {
            for (core_no = 0; core_no < topo.cores_per_node;
                 ++core_no) {
                for (thread_no = 0; thread_no <
                                    topo.threads_per_core; ++thread_no) {
                    struct thread_data *t, *t2;

                    t = GET_THREAD(thread_base, thread_no,
                                   core_no, node_no,
                                   pkg_no);

                    if (cpu_is_not_present(t->cpu_id))
                        continue;

                    t2 = GET_THREAD(thread_base2, thread_no,
                                    core_no, node_no,
                                    pkg_no);

                    retval = func(t, t2);
                    if (retval)
                        return retval;
                }
            }
        }
    }
    return 0;
}

int for_all_proc_cpus(int (func)(int))
{
	FILE *fp;
	int cpu_num;
	int retval;

	fp = fopen_or_die(proc_stat, "r");

	retval = fscanf(fp, "cpu %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d\n");
	if (retval != 0)
		err(1, "%s: failed to parse format", proc_stat);
	while (1) {
		retval = fscanf(fp, "cpu%u %*d %*d %*d %*d %*d %*d %*d %*d %*d %*d\n", &cpu_num);
        if (retval != 1)
			break;

		retval = func(cpu_num);

		if (retval) {
			fclose(fp);
			return(retval);
		}
	}
	fclose(fp);
	return 0;
}

int delta_thread(struct thread_data *new, struct thread_data *old)
{
    int i;
    struct msr_counter *mp;

    /* we run cpuid just the 1st time, copy the results */
    if (DO_BIC(BIC_APIC))
        new->apic_id = old->apic_id;
    if (DO_BIC(BIC_X2APIC))
        new->x2apic_id = old->x2apic_id;

    /*
     * the timestamps from start of measurement interval are in "old"
     * the timestamp from end of measurement interval are in "new"
     * over-write old w/ new so we can print end of interval values
     */

    timersub(&new->tv_begin, &old->tv_begin, &old->tv_delta);
    old->tv_begin = new->tv_begin;
    old->tv_end = new->tv_end;

    old->tsc = new->tsc - old->tsc;

    /* check for TSC < 1 Mcycles over interval */
    if (old->tsc < (1000 * 1000))
        errx(-3, "Insanely slow TSC rate, TSC stops in idle?\n"
                 "You can disable all c-states by booting with \"idle=poll\"\n"
                 "or just the deep ones with \"processor.max_cstate=1\"");


    //if (DO_BIC(BIC_Avg_MHz) || DO_BIC(BIC_Busy) || DO_BIC(BIC_Bzy_MHz)) {
    if (1) {
            if ((new->aperf > old->aperf) && (new->mperf > old->mperf)) {
                old->aperf = new->aperf - old->aperf;
                old->mperf = new->mperf - old->mperf;
            } else {
                return -1;
            }
        }

    if (old->mperf == 0) {
        if (debug > 1)
            fprintf(outf, "cpu%d MPERF 0!\n", old->cpu_id);
        old->mperf = 1;	/* divide by 0 protection */
    }
    for (i = 0, mp = sys.tp; mp; i++, mp = mp->next) {
        if (mp->format == FORMAT_RAW)
            old->counter[i] = new->counter[i];
        else
            old->counter[i] = new->counter[i] - old->counter[i];
    }
    return 0;
}

void free_fd_percpu(void)
{
    int i;

    for (i = 0; i < topo.max_cpu_num + 1; ++i) {
        if (fd_percpu[i] != 0)
            close(fd_percpu[i]);
    }

    free(fd_percpu);
}

void free_all_buffers(void)
{
    int i;

    CPU_FREE(cpu_present_set);
    cpu_present_set = NULL;
    cpu_present_setsize = 0;

    CPU_FREE(cpu_affinity_set);
    cpu_affinity_set = NULL;
    cpu_affinity_setsize = 0;

    free(thread_even);

    thread_even = NULL;

    free(thread_odd);

    thread_odd = NULL;

    free(output_buffer);
    output_buffer = NULL;
    outp = NULL;

    free_fd_percpu();

    free(irq_column_2_cpu);
    free(irqs_per_cpu);

    for (i = 0; i <= topo.max_cpu_num; ++i) {
        if (cpus[i].put_ids)
            CPU_FREE(cpus[i].put_ids);
    }
    free(cpus);
}

/*
 * Parse a file containing a single int.
 * Return 0 if file can not be opened
 * Exit if file can be opened, but can not be parsed
 */

void re_initialize(void)
{
    free_all_buffers();
    setup_all_buffers();
    printf("turbostat: re-initialized with num_cpus %d\n", topo.num_cpus);
}



int get_physical_package_id(int cpu)
{
    return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/physical_package_id", cpu);
}

int get_die_id(int cpu)
{
    return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/die_id", cpu);
}

int get_core_id(int cpu)
{
    return parse_int_file("/sys/devices/system/cpu/cpu%d/topology/core_id", cpu);
}

void set_node_data(void)
{
    int pkg, node, lnode, cpu, cpux;
    int cpu_count;

    /* initialize logical_node_id */
    for (cpu = 0; cpu <= topo.max_cpu_num; ++cpu)
        cpus[cpu].logical_node_id = -1;

    cpu_count = 0;
    for (pkg = 0; pkg < topo.num_packages; pkg++) {
        lnode = 0;
        for (cpu = 0; cpu <= topo.max_cpu_num; ++cpu) {
            if (cpus[cpu].physical_package_id != pkg)
                continue;
            /* find a cpu with an unset logical_node_id */
            if (cpus[cpu].logical_node_id != -1)
                continue;
            cpus[cpu].logical_node_id = lnode;
            node = cpus[cpu].physical_node_id;
            cpu_count++;
            /*
             * find all matching cpus on this pkg and set
             * the logical_node_id
             */
            for (cpux = cpu; cpux <= topo.max_cpu_num; cpux++) {
                if ((cpus[cpux].physical_package_id == pkg) &&
                    (cpus[cpux].physical_node_id == node)) {
                    cpus[cpux].logical_node_id = lnode;
                    cpu_count++;
                }
            }
            lnode++;
            if (lnode > topo.nodes_per_pkg)
                topo.nodes_per_pkg = lnode;
        }
        if (cpu_count >= topo.max_cpu_num)
            break;
    }
}

int get_physical_node_id(struct cpu_topology *thiscpu)
{
    char path[80];
    FILE *filep;
    int i;
    int cpu = thiscpu->logical_cpu_id;

    for (i = 0; i <= topo.max_cpu_num; i++) {
        sprintf(path, "/sys/devices/system/cpu/cpu%d/node%i/cpulist",
                cpu, i);
        filep = fopen(path, "r");
        if (!filep)
            continue;
        fclose(filep);
        return i;
    }
    return -1;
}

int get_thread_siblings(struct cpu_topology *thiscpu)
{
    char path[80], character;
    FILE *filep;
    unsigned long map;
    int so, shift, sib_core;
    int cpu = thiscpu->logical_cpu_id;
    int offset = topo.max_cpu_num + 1;
    size_t size;
    int thread_id = 0;

    thiscpu->put_ids = CPU_ALLOC((topo.max_cpu_num + 1));
    if (thiscpu->thread_id < 0)
        thiscpu->thread_id = thread_id++;
    if (!thiscpu->put_ids)
        return -1;

    size = CPU_ALLOC_SIZE((topo.max_cpu_num + 1));
    CPU_ZERO_S(size, thiscpu->put_ids);

    sprintf(path,
            "/sys/devices/system/cpu/cpu%d/topology/thread_siblings", cpu);
    filep = fopen_or_die(path, "r");
    do {
        offset -= BITMASK_SIZE;
        if (fscanf(filep, "%lx%c", &map, &character) != 2)
            err(1, "%s: failed to parse file", path);
        for (shift = 0; shift < BITMASK_SIZE; shift++) {
            if ((map >> shift) & 0x1) {
                so = shift + offset;
                sib_core = get_core_id(so);
                if (sib_core == thiscpu->physical_core_id) {
                    CPU_SET_S(so, size, thiscpu->put_ids);
                    if ((so != cpu) &&
                        (cpus[so].thread_id < 0))
                        cpus[so].thread_id =
                                thread_id++;
                }
            }
        }
    } while (!strncmp(&character, ",", 1));
    fclose(filep);

    return CPU_COUNT_S(size, thiscpu->put_ids);
}


int dir_filter(const struct dirent *dirp)
{
	if (isdigit(dirp->d_name[0]))
		return 1;
	else
		return 0;
}

int open_dev_cpu_msr(int dummy1)
{
	return 0;
}


    void set_max_cpu_num(void)
    {
        FILE *filep;
        unsigned long dummy;

        topo.max_cpu_num = 0;
        filep = fopen_or_die(
                "/sys/devices/system/cpu/cpu0/topology/thread_siblings",
                "r");
        while (fscanf(filep, "%lx,", &dummy) == 1)
            topo.max_cpu_num += BITMASK_SIZE;
        fclose(filep);
        topo.max_cpu_num--; /* 0 based */
    }

/*
 * count_cpus()
 * remember the last one seen, it will be the max
 */
    int count_cpus(int cpu)
    {
        topo.num_cpus++;
        return 0;
    }
    int mark_cpu_present(int cpu)
    {
        CPU_SET_S(cpu, cpu_present_setsize, cpu_present_set);
        return 0;
    }

    int init_thread_id(int cpu)
    {
        cpus[cpu].thread_id = -1;
        return 0;
    }

void topology_probe()
{
	int i;
	int max_core_id = 0;
	int max_package_id = 0;
	int max_die_id = 0;
	int max_siblings = 0;

	/* Initialize num_cpus, max_cpu_num */
	set_max_cpu_num();
	topo.num_cpus = 0;
	for_all_proc_cpus(count_cpus);
	if (!summary_only && topo.num_cpus > 1)
		BIC_PRESENT(BIC_CPU);

    fprintf(stdout, ">>>>>>num_cpus %d max_cpu_num %d\n", topo.num_cpus, topo.max_cpu_num);
    fflush(stdout);

	if (debug > 1)
		fprintf(outf, "num_cpus %d max_cpu_num %d\n", topo.num_cpus, topo.max_cpu_num);

	cpus = calloc(1, (topo.max_cpu_num  + 1) * sizeof(struct cpu_topology));
	if (cpus == NULL)
		err(1, "calloc cpus");

	/*
	 * Allocate and initialize cpu_present_set
	 */
	cpu_present_set = CPU_ALLOC((topo.max_cpu_num + 1));
	if (cpu_present_set == NULL)
		err(3, "CPU_ALLOC");
	cpu_present_setsize = CPU_ALLOC_SIZE((topo.max_cpu_num + 1));
	CPU_ZERO_S(cpu_present_setsize, cpu_present_set);
	for_all_proc_cpus(mark_cpu_present);

	/*
	 * Validate that all cpus in cpu_subset are also in cpu_present_set
	 */
	for (i = 0; i < CPU_SUBSET_MAXCPUS; ++i) {
		if (CPU_ISSET_S(i, cpu_subset_size, cpu_subset))
			if (!CPU_ISSET_S(i, cpu_present_setsize, cpu_present_set))
				err(1, "cpu%d not present", i);
	}

	/*
	 * Allocate and initialize cpu_affinity_set
	 */
	cpu_affinity_set = CPU_ALLOC((topo.max_cpu_num + 1));
	if (cpu_affinity_set == NULL)
		err(3, "CPU_ALLOC");
	cpu_affinity_setsize = CPU_ALLOC_SIZE((topo.max_cpu_num + 1));
	CPU_ZERO_S(cpu_affinity_setsize, cpu_affinity_set);

	for_all_proc_cpus(init_thread_id);

	/*
	 * For online cpus
	 * find max_core_id, max_package_id
	 */
	for (i = 0; i <= topo.max_cpu_num; ++i) {
		int siblings;

		if (cpu_is_not_present(i)) {
			if (debug > 1)
				fprintf(outf, "cpu%d NOT PRESENT\n", i);
			continue;
		}

		cpus[i].logical_cpu_id = i;

		/* get package information */
		cpus[i].physical_package_id = get_physical_package_id(i);
		if (cpus[i].physical_package_id > max_package_id)
			max_package_id = cpus[i].physical_package_id;

		/* get die information */
		cpus[i].die_id = get_die_id(i);
		if (cpus[i].die_id > max_die_id)
			max_die_id = cpus[i].die_id;

		/* get numa node information */
		cpus[i].physical_node_id = get_physical_node_id(&cpus[i]);
		if (cpus[i].physical_node_id > topo.max_node_num)
			topo.max_node_num = cpus[i].physical_node_id;

		/* get core information */
		cpus[i].physical_core_id = get_core_id(i);
		if (cpus[i].physical_core_id > max_core_id)
			max_core_id = cpus[i].physical_core_id;

		/* get thread information */
		siblings = get_thread_siblings(&cpus[i]);
		if (siblings > max_siblings)
			max_siblings = siblings;
		if (cpus[i].thread_id == 0)
			topo.num_cores++;
	}

	topo.cores_per_node = max_core_id + 1;
	if (debug > 1)
		fprintf(outf, "max_core_id %d, sizing for %d cores per package\n",
			max_core_id, topo.cores_per_node);
	if (!summary_only && topo.cores_per_node > 1)
		BIC_PRESENT(BIC_Core);

	topo.num_die = max_die_id + 1;
	if (debug > 1)
		fprintf(outf, "max_die_id %d, sizing for %d die\n",
				max_die_id, topo.num_die);
	if (!summary_only && topo.num_die > 1)
		BIC_PRESENT(BIC_Die);

	topo.num_packages = max_package_id + 1;
	if (debug > 1)
		fprintf(outf, "max_package_id %d, sizing for %d packages\n",
			max_package_id, topo.num_packages);
	if (!summary_only && topo.num_packages > 1)
		BIC_PRESENT(BIC_Package);

	set_node_data();
	if (debug > 1)
		fprintf(outf, "nodes_per_pkg %d\n", topo.nodes_per_pkg);
	if (!summary_only && topo.nodes_per_pkg > 1)
		BIC_PRESENT(BIC_Node);

	topo.threads_per_core = max_siblings;
	if (debug > 1)
		fprintf(outf, "max_siblings %d\n", max_siblings);

	if (debug < 1)
		return;

	for (i = 0; i <= topo.max_cpu_num; ++i) {
		if (cpu_is_not_present(i))
			continue;
		fprintf(outf,
			"cpu %d pkg %d die %d node %d lnode %d core %d thread %d\n",
			i, cpus[i].physical_package_id, cpus[i].die_id,
			cpus[i].physical_node_id,
			cpus[i].logical_node_id,
			cpus[i].physical_core_id,
			cpus[i].thread_id);
	}

}



void allocate_output_buffer()
{
	output_buffer = calloc(1, (1 + topo.num_cpus) * 2048);
	outp = output_buffer;
	if (outp == NULL)
		err(-1, "calloc output buffer");
}
void allocate_fd_percpu(void)
{
	fd_percpu = calloc(topo.max_cpu_num + 1, sizeof(int));
	if (fd_percpu == NULL)
		err(-1, "calloc fd_percpu");
}
void allocate_irq_buffers(void)
{
	irq_column_2_cpu = calloc(topo.num_cpus, sizeof(int));
	if (irq_column_2_cpu == NULL)
		err(-1, "calloc %d", topo.num_cpus);

	irqs_per_cpu = calloc(topo.max_cpu_num + 1, sizeof(int));
	if (irqs_per_cpu == NULL)
		err(-1, "calloc %d", topo.max_cpu_num + 1);
}

void setup_all_buffers(void)
{
    topology_probe();
    allocate_irq_buffers();
    allocate_fd_percpu();
    allocate_counters(&thread_even);
    allocate_counters(&thread_odd);
    allocate_output_buffer();
    for_all_proc_cpus(initialize_counters);
}

void set_base_cpu(void)
{
    base_cpu = sched_getcpu();
    if (base_cpu < 0)
        err(-ENODEV, "No valid cpus found");

    if (debug > 1)
        fprintf(outf, "base_cpu = %d\n", base_cpu);
}


void check_dev_msr()
{
	struct stat sb;
	char pathname[32];

	sprintf(pathname, "/dev/cpu/%d/msr", base_cpu);
	if (stat(pathname, &sb))
 		if (system("/sbin/modprobe msr > /dev/null 2>&1"))
			err(-5, "no /dev/cpu/0/msr, Try \"# modprobe msr\" ");
}

void check_permissions()
{
	struct __user_cap_header_struct cap_header_data;
	cap_user_header_t cap_header = &cap_header_data;
	struct __user_cap_data_struct cap_data_data;
	cap_user_data_t cap_data = &cap_data_data;
	extern int capget(cap_user_header_t hdrp, cap_user_data_t datap);
	int do_exit = 0;
	char pathname[32];

	/* check for CAP_SYS_RAWIO */
	cap_header->pid = getpid();
	cap_header->version = _LINUX_CAPABILITY_VERSION;
	if (capget(cap_header, cap_data) < 0)
		err(-6, "capget(2) failed");

	if ((cap_data->effective & (1 << CAP_SYS_RAWIO)) == 0) {
		do_exit++;
		warnx("capget(CAP_SYS_RAWIO) failed,"
			" try \"# setcap cap_sys_rawio=ep %s\"", progname);
	}

	/* test file permissions */
	sprintf(pathname, "/dev/cpu/%d/msr", base_cpu);
	if (euidaccess(pathname, R_OK)) {
		do_exit++;
		warn("/dev/cpu/0/msr open failed, try chown or chmod +r /dev/cpu/*/msr");
	}

	/* if all else fails, thell them to be root */
	if (do_exit)
		if (getuid() != 0)
			warnx("... or simply run as root");

	if (do_exit)
		exit(-6);
}


int monitor_init()
{
    setup_all_buffers();
    set_base_cpu();
    check_dev_msr();
    check_permissions();
    return 0;
    //process_cpuid();
}


int exit_requested;

static void signal_handler (int signal)
{
    switch (signal) {
        case SIGINT:
            exit_requested = 1;
            if (debug)
                fprintf(stderr, " SIGINT\n");
            break;
        case SIGUSR1:
            if (debug > 1)
                fprintf(stderr, "SIGUSR1\n");
            break;
    }
}

void setup_signal_handler(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = &signal_handler;

    if (sigaction(SIGINT, &sa, NULL) < 0)
        err(1, "sigaction SIGINT");
    if (sigaction(SIGUSR1, &sa, NULL) < 0)
        err(1, "sigaction SIGUSR1");
}

void do_sleep(void)
{
    struct timeval tout;
    struct timespec rest;
    fd_set readfds;
    int retval;

    FD_ZERO(&readfds);
    FD_SET(0, &readfds);

    if (ignore_stdin) {
        nanosleep(&interval_ts, NULL);
        return;
    }

    tout = interval_tv;
    retval = select(1, &readfds, NULL, NULL, &tout);

    if (retval == 1) {
        switch (getc(stdin)) {
            case 'q':
                exit_requested = 1;
                break;
            case EOF:
                /*
                 * 'stdin' is a pipe closed on the other end. There
                 * won't be any further input.
                 */
                ignore_stdin = 1;
                /* Sleep the rest of the time */
                rest.tv_sec = (tout.tv_sec + tout.tv_usec / 1000000);
                rest.tv_nsec = (tout.tv_usec % 1000000) * 1000;
                nanosleep(&rest, NULL);
        }
    }
}

int show_freq(struct thread_data *t)
{
    double interval_float, tsc;
    interval_float = t->tv_delta.tv_sec + t->tv_delta.tv_usec/1000000.0;
    tsc = t->tsc * tsc_tweak;
    printf("cpu%d: Bzy Freq: %.0f\n",
            t->cpu_id, tsc / units * t->aperf / t->mperf / interval_float);
    return 0;
}

int output_freq(struct thread_data *t)
{
    double interval_float, tsc;
    interval_float = t->tv_delta.tv_sec + t->tv_delta.tv_usec/1000000.0;
    tsc = t->tsc * tsc_tweak;
    output[t->cpu_id] = tsc / units * t->aperf / t->mperf / interval_float;
    //printf("cpu%d: Bzy Freq: %.0f\n",
    //       t->cpu_id, tsc / units * t->aperf / t->mperf / interval_float);
    return 0;
}


void monitor_loop(int interval, int round)
{
    int retval;
    int restarted = 0;
    int done_iters = 0;
    if (interval > 0){
        interval_tv.tv_sec = interval;
        interval_ts.tv_sec = interval;
    }
    if (round >0){
        num_iterations = round;
    }

    setup_signal_handler();

    restart:
    restarted++;

    //snapshot_proc_sysfs_files();
    retval = for_all_cpus(get_counters, EVEN_COUNTERS);
    first_counter_read = 0;
    if (retval < -1) {
        exit(retval);
    } else if (retval == -1) {
        if (restarted > 1) {
            exit(retval);
        }
        re_initialize();
        goto restart;
    }
    restarted = 0;
    done_iters = 0;
    gettimeofday(&tv_even, (struct timezone *)NULL);

    while (1) {
        if (for_all_proc_cpus(cpu_is_not_present)) {

            re_initialize();

            goto restart;
        }
        do_sleep();
        //if (snapshot_proc_sysfs_files())
            //goto restart;
        retval = for_all_cpus(get_counters, ODD_COUNTERS);
        if (retval < -1) {
            exit(retval);
        } else if (retval == -1) {
            re_initialize();
            goto restart;
        }
        gettimeofday(&tv_odd, (struct timezone *)NULL);
        timersub(&tv_odd, &tv_even, &tv_delta);
        if (for_all_cpus_2(delta_thread, ODD_COUNTERS, EVEN_COUNTERS)) {
            re_initialize();
            goto restart;
        }
        //retval = for_all_cpus(show_freq, EVEN_COUNTERS);
        retval = for_all_cpus(output_freq, EVEN_COUNTERS);
        //compute_average(EVEN_COUNTERS);
        //format_all_counters(EVEN_COUNTERS);
        //fflush(stdout);
        if (exit_requested)
            break;
        if (num_iterations && ++done_iters >= num_iterations)
            break;
        do_sleep();
        //if (snapshot_proc_sysfs_files())
            //goto restart;
        retval = for_all_cpus(get_counters, EVEN_COUNTERS);
        if (retval < -1) {
            exit(retval);
        } else if (retval == -1) {
            re_initialize();
            goto restart;
        }
        gettimeofday(&tv_even, (struct timezone *)NULL);
        timersub(&tv_even, &tv_odd, &tv_delta);
        if (for_all_cpus_2(delta_thread, EVEN_COUNTERS, ODD_COUNTERS)) {
            re_initialize();
            goto restart;
        }
        //retval = for_all_cpus(show_freq, ODD_COUNTERS);
        retval = for_all_cpus(output_freq, ODD_COUNTERS);
        //compute_average(ODD_COUNTERS);
        //format_all_counters(ODD_COUNTERS);
        if (exit_requested)
            break;
        if (num_iterations && ++done_iters >= num_iterations)
            break;
    }
}
