// SPDX-License-Identifier: GPL-2.0
/*
 * Non-trivial C macros cannot be used in Rust. Similarly, inlined C functions
 * cannot be called either. This file explicitly creates functions ("helpers")
 * that wrap those so that they can be called from Rust.
 *
 * Even though Rust kernel modules should never use directly the bindings, some
 * of these helpers need to be exported because Rust generics and inlined
 * functions may not get their code generated in the crate where they are
 * defined. Other helpers, called from non-inline functions, may not be
 * exported, in principle. However, in general, the Rust compiler does not
 * guarantee codegen will be performed for a non-inline function either.
 * Therefore, this file exports all the helpers. In the future, this may be
 * revisited to reduce the number of exports after the compiler is informed
 * about the places codegen is required.
 *
 * All symbols are exported as GPL-only to guarantee no GPL-only feature is
 * accidentally exposed.
 *
 * Sorted alphabetically.
 */

#include <kunit/test-bug.h>
#include <linux/bug.h>
#include <linux/build_bug.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/errname.h>
#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/security.h>
#include <linux/spinlock.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/irq_pipeline.h>
#include <linux/irq_work.h>
#include <asm-generic/irq_pipeline.h>
#include <linux/hashtable.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/refcount.h>
#include <linux/skbuff.h>
#include <uapi/linux/types.h>
#include <linux/if_packet.h>
#include <linux/notifier.h>
#include <linux/interrupt.h>
#include <linux/slab.h>

#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/uio.h>
#include <linux/kthread.h>
#include <linux/platform_device.h>
#include <linux/cpumask.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/percpu-defs.h>
#include <linux/percpu.h>
#include <asm/io.h>
#include <linux/irq.h>
#include <linux/irqchip/chained_irq.h>
#include <linux/irqdomain.h>
#include <linux/amba/bus.h>
#include <linux/of_device.h>
#include <linux/device/class.h>
#include <linux/export.h>
#include <linux/module.h>
#include <linux/irq_pipeline.h>
#include <linux/tick.h>
#include <linux/netdevice.h>
#include <linux/net.h>
#include <net/net_namespace.h>
#include <linux/completion.h>
#include <linux/irqstage.h>
#include <linux/preempt.h>
#include <linux/signal_types.h>
#include <asm/uaccess.h>
#include <linux/dovetail.h>
#include <linux/spinlock_pipeline.h>
#include <linux/log2.h>
#include <linux/capability.h>
#include <linux/spinlock_types.h>

#include <net/sock.h>
#include <linux/jhash.h>
#include <linux/bottom_half.h>
#include <linux/if_vlan.h>
#include <linux/kdev_t.h>

__noreturn void rust_helper_BUG(void)
{
	BUG();
}
EXPORT_SYMBOL_GPL(rust_helper_BUG);

void rust_helper_mutex_lock(struct mutex *lock)
{
	mutex_lock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_mutex_lock);

void rust_helper___spin_lock_init(spinlock_t *lock, const char *name,
				  struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	__raw_spin_lock_init(spinlock_check(lock), name, key, LD_WAIT_CONFIG);
#else
	spin_lock_init(lock);
#endif
}
EXPORT_SYMBOL_GPL(rust_helper___spin_lock_init);

void rust_helper_spin_lock(spinlock_t *lock)
{
	spin_lock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_spin_lock);

void rust_helper_spin_unlock(spinlock_t *lock)
{
	spin_unlock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_spin_unlock);

void rust_helper_init_wait(struct wait_queue_entry *wq_entry)
{
	init_wait(wq_entry);
}
EXPORT_SYMBOL_GPL(rust_helper_init_wait);

int rust_helper_signal_pending(struct task_struct *t)
{
	return signal_pending(t);
}
EXPORT_SYMBOL_GPL(rust_helper_signal_pending);

refcount_t rust_helper_REFCOUNT_INIT(int n)
{
	return (refcount_t)REFCOUNT_INIT(n);
}
EXPORT_SYMBOL_GPL(rust_helper_REFCOUNT_INIT);

void rust_helper_refcount_inc(refcount_t *r)
{
	refcount_inc(r);
}
EXPORT_SYMBOL_GPL(rust_helper_refcount_inc);

bool rust_helper_refcount_dec_and_test(refcount_t *r)
{
	return refcount_dec_and_test(r);
}
EXPORT_SYMBOL_GPL(rust_helper_refcount_dec_and_test);

__force void *rust_helper_ERR_PTR(long err)
{
	return ERR_PTR(err);
}
EXPORT_SYMBOL_GPL(rust_helper_ERR_PTR);

bool rust_helper_IS_ERR(__force const void *ptr)
{
	return IS_ERR(ptr);
}
EXPORT_SYMBOL_GPL(rust_helper_IS_ERR);

long rust_helper_PTR_ERR(__force const void *ptr)
{
	return PTR_ERR(ptr);
}
EXPORT_SYMBOL_GPL(rust_helper_PTR_ERR);

const char *rust_helper_errname(int err)
{
	return errname(err);
}
EXPORT_SYMBOL_GPL(rust_helper_errname);

struct task_struct *rust_helper_get_current(void)
{
	return current;
}
EXPORT_SYMBOL_GPL(rust_helper_get_current);

void rust_helper_get_task_struct(struct task_struct *t)
{
	get_task_struct(t);
}
EXPORT_SYMBOL_GPL(rust_helper_get_task_struct);

void rust_helper_put_task_struct(struct task_struct *t)
{
	put_task_struct(t);
}
EXPORT_SYMBOL_GPL(rust_helper_put_task_struct);

kuid_t rust_helper_task_uid(struct task_struct *task)
{
	return task_uid(task);
}
EXPORT_SYMBOL_GPL(rust_helper_task_uid);

kuid_t rust_helper_task_euid(struct task_struct *task)
{
	return task_euid(task);
}
EXPORT_SYMBOL_GPL(rust_helper_task_euid);

#ifndef CONFIG_USER_NS
uid_t rust_helper_from_kuid(struct user_namespace *to, kuid_t uid)
{
	return from_kuid(to, uid);
}
EXPORT_SYMBOL_GPL(rust_helper_from_kuid);
#endif /* CONFIG_USER_NS */

bool rust_helper_uid_eq(kuid_t left, kuid_t right)
{
	return uid_eq(left, right);
}
EXPORT_SYMBOL_GPL(rust_helper_uid_eq);

kuid_t rust_helper_current_euid(void)
{
	return current_euid();
}
EXPORT_SYMBOL_GPL(rust_helper_current_euid);

struct user_namespace *rust_helper_current_user_ns(void)
{
	return current_user_ns();
}
EXPORT_SYMBOL_GPL(rust_helper_current_user_ns);

pid_t rust_helper_task_tgid_nr_ns(struct task_struct *tsk,
				  struct pid_namespace *ns)
{
	return task_tgid_nr_ns(tsk, ns);
}
EXPORT_SYMBOL_GPL(rust_helper_task_tgid_nr_ns);

struct kunit *rust_helper_kunit_get_current_test(void)
{
	return kunit_get_current_test();
}
EXPORT_SYMBOL_GPL(rust_helper_kunit_get_current_test);

void rust_helper_init_work_with_key(struct work_struct *work, work_func_t func,
				    bool onstack, const char *name,
				    struct lock_class_key *key)
{
	__init_work(work, onstack);
	work->data = (atomic_long_t)WORK_DATA_INIT();
	lockdep_init_map(&work->lockdep_map, name, key, 0);
	INIT_LIST_HEAD(&work->entry);
	work->func = func;
}
EXPORT_SYMBOL_GPL(rust_helper_init_work_with_key);

struct file *rust_helper_get_file(struct file *f)
{
	return get_file(f);
}
EXPORT_SYMBOL_GPL(rust_helper_get_file);

const struct cred *rust_helper_get_cred(const struct cred *cred)
{
	return get_cred(cred);
}
EXPORT_SYMBOL_GPL(rust_helper_get_cred);

void rust_helper_put_cred(const struct cred *cred)
{
	put_cred(cred);
}
EXPORT_SYMBOL_GPL(rust_helper_put_cred);

#ifndef CONFIG_SECURITY
void rust_helper_security_cred_getsecid(const struct cred *c, u32 *secid)
{
	security_cred_getsecid(c, secid);
}
EXPORT_SYMBOL_GPL(rust_helper_security_cred_getsecid);

int rust_helper_security_secid_to_secctx(u32 secid, char **secdata, u32 *seclen)
{
	return security_secid_to_secctx(secid, secdata, seclen);
}
EXPORT_SYMBOL_GPL(rust_helper_security_secid_to_secctx);

void rust_helper_security_release_secctx(char *secdata, u32 seclen)
{
	security_release_secctx(secdata, seclen);
}
EXPORT_SYMBOL_GPL(rust_helper_security_release_secctx);
#endif

/*
 * `bindgen` binds the C `size_t` type as the Rust `usize` type, so we can
 * use it in contexts where Rust expects a `usize` like slice (array) indices.
 * `usize` is defined to be the same as C's `uintptr_t` type (can hold any
 * pointer) but not necessarily the same as `size_t` (can hold the size of any
 * single object). Most modern platforms use the same concrete integer type for
 * both of them, but in case we find ourselves on a platform where
 * that's not true, fail early instead of risking ABI or
 * integer-overflow issues.
 *
 * If your platform fails this assertion, it means that you are in
 * danger of integer-overflow bugs (even if you attempt to add
 * `--no-size_t-is-usize`). It may be easiest to change the kernel ABI on
 * your platform such that `size_t` matches `uintptr_t` (i.e., to increase
 * `size_t`, because `uintptr_t` has to be at least as big as `size_t`).
 */
static_assert(
	sizeof(size_t) == sizeof(uintptr_t) &&
	__alignof__(size_t) == __alignof__(uintptr_t),
	"Rust code expects C `size_t` to match Rust `usize`"
);


ktime_t rust_helper_ktime_add_ns(ktime_t kt, u64 nsval) {
	return ktime_add_ns(kt,nsval);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_add_ns);

ktime_t rust_helper_ktime_add(ktime_t kt, ktime_t nsval) {
	return ktime_add(kt,nsval);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_add);

ktime_t rust_helper_ktime_sub(ktime_t lhs,ktime_t rhs)
{
	return ktime_sub(lhs, rhs);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_sub);

ktime_t rust_helper_ktime_compare(ktime_t cmp1, ktime_t cmp2) {
	return ktime_compare(cmp1,cmp2);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_compare);

ktime_t rust_helper_ktime_set(const s64 secs, const unsigned long nsecs) {
	return ktime_set(secs,nsecs);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_set);

s64 rust_helper_timespec64_to_ktime(struct timespec64 ts) {
	return ktime_set(ts.tv_sec, ts.tv_nsec);
}
EXPORT_SYMBOL_GPL(rust_helper_timespec64_to_ktime);

s64 rust_helper_ktime_divns(const ktime_t kt, s64 div) {
	return ktime_divns(kt,div);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_divns);

struct timespec64 rust_helper_ktime_to_timespec64(ktime_t kt) {
	return ktime_to_timespec64(kt);
}
EXPORT_SYMBOL_GPL(rust_helper_ktime_to_timespec64);

void rust_helper_irq_send_oob_ipi(unsigned int ipi,
		const struct cpumask *cpumask) {
	irq_send_oob_ipi(ipi, cpumask);
}
EXPORT_SYMBOL_GPL(rust_helper_irq_send_oob_ipi);

unsigned int rust_helper_irq_get_TIMER_OOB_IPI(void) {
	return TIMER_OOB_IPI;
}
EXPORT_SYMBOL_GPL(rust_helper_irq_get_TIMER_OOB_IPI);

unsigned int rust_helper_irq_get_RESCHEDULE_OOB_IPI(void) {
	return RESCHEDULE_OOB_IPI;
}
EXPORT_SYMBOL_GPL(rust_helper_irq_get_RESCHEDULE_OOB_IPI);

void rust_helper_init_irq_work(struct irq_work *work, void (*func)(struct irq_work *))
{
	init_irq_work(work, func);
}
EXPORT_SYMBOL_GPL(rust_helper_init_irq_work);

void rust_helper_hash_init(struct hlist_head *ht, unsigned int sz)
{
	__hash_init(ht, sz);
}
EXPORT_SYMBOL_GPL(rust_helper_hash_init);

void rust_helper_rcu_read_lock(void)
{
	rcu_read_lock();
}
EXPORT_SYMBOL_GPL(rust_helper_rcu_read_lock);

void rust_helper_rcu_read_unlock(void)
{
	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(rust_helper_rcu_read_unlock);

int rust_helper_cond_resched(void)
{
	return cond_resched();
}
EXPORT_SYMBOL_GPL(rust_helper_cond_resched);

unsigned long rust_helper_copy_from_user(void *to, const void __user *from, unsigned long n)
{
	return copy_from_user(to, from, n);
}

unsigned long rust_helper_copy_to_user(void __user *to, const void *from, unsigned long n)
{
	return copy_to_user(to, from, n);
}

unsigned long rust_helper_clear_user(void __user *to, unsigned long n)
{
	return clear_user(to, n);
}

refcount_t rust_helper_refcount_new(void)
{
	return (refcount_t)REFCOUNT_INIT(1);
}
EXPORT_SYMBOL_GPL(rust_helper_refcount_new);

void rust_helper_dev_hold(struct net_device *dev)
{
	return dev_hold(dev);
}
EXPORT_SYMBOL_GPL(rust_helper_dev_hold);

void rust_helper_dev_put(struct net_device *dev)
{
	return dev_put(dev);
}
EXPORT_SYMBOL_GPL(rust_helper_dev_put);

struct net *rust_helper_get_net(struct net *net)
{
	return get_net(net);
}
EXPORT_SYMBOL_GPL(rust_helper_get_net);

void rust_helper_put_net(struct net *net)
{
	return put_net(net);
}
EXPORT_SYMBOL_GPL(rust_helper_put_net);

void* rust_helper_kzalloc(size_t size, gfp_t flags)
{
	return kzalloc(size, flags);
}
EXPORT_SYMBOL_GPL(rust_helper_kzalloc); 

void rust_helper_add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	struct list_head *head = &wq_head->head;
	struct wait_queue_entry *wq;
	list_for_each_entry(wq, &wq_head->head, entry) {
		if (!(wq->flags & (0x20)))
			break;
		head = &wq->entry;
	}
	list_add(&wq_entry->entry, head);
}
EXPORT_SYMBOL_GPL(rust_helper_add_wait_queue);

int rust_helper_wait_event_interruptible(struct wait_queue_head *wq_head, bool condition)
{
	return wait_event_interruptible(*wq_head, condition);
}
EXPORT_SYMBOL_GPL(rust_helper_wait_event_interruptible);

void rust_helper_init_waitqueue_head(struct wait_queue_head *wq_head) {
	init_waitqueue_head(wq_head);
}
EXPORT_SYMBOL_GPL(rust_helper_init_waitqueue_head);

//NOTE: rust_helper for stax
unsigned long rust_helper_spin_lock_irqsave(spinlock_t *lock) {
	unsigned long flags;
	spin_lock_irqsave(lock, flags);
	return flags;
}
EXPORT_SYMBOL_GPL(rust_helper_spin_lock_irqsave);

void rust_helper_spin_unlock_irqrestore(spinlock_t *lock, unsigned long flags)
{
	spin_unlock_irqrestore(lock, flags);
}
EXPORT_SYMBOL_GPL(rust_helper_spin_unlock_irqrestore);

bool rust_helper_wq_has_sleeper(struct wait_queue_head *wq_head)
{
	return wq_has_sleeper(wq_head);
}
EXPORT_SYMBOL_GPL(rust_helper_wq_has_sleeper);

unsigned long rust_helper_raw_spin_lock_irqsave(hard_spinlock_t *lock) {
	unsigned long flags;
	raw_spin_lock_irqsave(lock, flags);
	return flags;
}
EXPORT_SYMBOL_GPL(rust_helper_raw_spin_lock_irqsave);

void rust_helper_raw_spin_unlock_irqrestore(hard_spinlock_t *lock, unsigned long flags) {
	raw_spin_unlock_irqrestore(lock, flags);
}
EXPORT_SYMBOL_GPL(rust_helper_raw_spin_unlock_irqrestore);

bool rust_helper_waitqueue_active(struct wait_queue_head *wq_head) {
	return !!waitqueue_active(wq_head);
}
EXPORT_SYMBOL_GPL(rust_helper_waitqueue_active);

bool rust_helper_list_empty(struct list_head *head) {
	return list_empty(head);
}
EXPORT_SYMBOL_GPL(rust_helper_list_empty);

void rust_helper_list_del(struct list_head *list)
{
	list_del(list);
}
EXPORT_SYMBOL_GPL(rust_helper_list_del);

void rust_helper_list_del_init(struct list_head *list)
{
	list_del_init(list);
}
EXPORT_SYMBOL_GPL(rust_helper_list_del_init);

const char * rust_helper_dev_name(struct device *dev)
{
	return dev_name(dev);
}
EXPORT_SYMBOL_GPL(rust_helper_dev_name);

void rust_helper_atomic_set(atomic_t *v, int i)
{
	atomic_set(v, i);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_set);

void rust_helper_atomic_inc(atomic_t *v)
{
	atomic_inc(v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_inc);

bool rust_helper_atomic_dec_and_test(atomic_t *v)
{
	return atomic_dec_and_test(v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_dec_and_test);

int rust_helper_atomic_dec_return(atomic_t *v)
{
	return atomic_dec_return(v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_dec_return);

int rust_helper_atomic_read(atomic_t *v)
{
	return atomic_read(v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_read);

void rust_helper_atomic_add(int i, atomic_t *v)
{
	return atomic_add(i, v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_add);

void rust_helper_atomic_sub(int i, atomic_t *v)
{
	return atomic_sub(i, v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_sub);

int rust_helper_atomic_sub_return(int i, atomic_t *v)
{
	return atomic_sub_return(i, v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_sub_return);

int rust_helper_atomic_cmpxchg(atomic_t *v, int old, int new)
{
	return atomic_cmpxchg(v, old, new);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_cmpxchg);

int rust_helper_atomic_add_return(int i, atomic_t *v)
{
	return atomic_add_return(i, v);
}
EXPORT_SYMBOL_GPL(rust_helper_atomic_add_return);

void rust_helper_spin_lock_init(spinlock_t *lock, const char *name,
				struct lock_class_key *key)
{
#ifdef CONFIG_DEBUG_SPINLOCK
	__spin_lock_init(lock, name, key);
#else
	spin_lock_init(lock);
#endif
}
EXPORT_SYMBOL_GPL(rust_helper_spin_lock_init);

void rust_helper_hard_spin_lock(struct raw_spinlock *rlock) {
	hard_spin_lock(rlock);
}
EXPORT_SYMBOL_GPL(rust_helper_hard_spin_lock);

void rust_helper_hard_spin_unlock(struct raw_spinlock *rlock) {
	hard_spin_unlock(rlock);
}
EXPORT_SYMBOL_GPL(rust_helper_hard_spin_unlock);

void rust_helper_raw_spin_lock(hard_spinlock_t *lock) {
	raw_spin_lock(lock);
}
EXPORT_SYMBOL_GPL(rust_helper_raw_spin_lock);

void rust_helper_raw_spin_lock_nested(hard_spinlock_t *lock, unsigned int depth) {
	raw_spin_lock_nested(lock, depth);
}
EXPORT_SYMBOL_GPL(rust_helper_raw_spin_lock_nested);

void rust_helper_init_completion(struct completion *x) {
	init_completion(x);
}
EXPORT_SYMBOL_GPL(rust_helper_init_completion);

struct class * rust_helper_class_create(const char* name)
{
	struct class *res = class_create(name);
	return res;
}
EXPORT_SYMBOL_GPL(rust_helper_class_create);

kernel_cap_t rust_helper_current_cap(void) {
	return current_cap();
}
EXPORT_SYMBOL_GPL(rust_helper_current_cap);

int rust_helper_cap_raised(kernel_cap_t c, int flag) {
	return cap_raised(c, flag);
}
EXPORT_SYMBOL_GPL(rust_helper_cap_raised);

void rust_helper__this_cpu_write(struct clock_proxy_device *pcp, struct clock_proxy_device *val)
{
	__this_cpu_write(pcp, val);
}
EXPORT_SYMBOL_GPL(rust_helper__this_cpu_write);

struct clock_proxy_device* rust_helper__this_cpu_read(struct clock_proxy_device *pcp)
{
	return __this_cpu_read(pcp);
}
EXPORT_SYMBOL_GPL(rust_helper__this_cpu_read);

int rust_helper_proxy_set(ktime_t expires,
				struct clock_event_device *dev)
{
	struct clock_event_device *real_dev = container_of(dev, struct clock_proxy_device, proxy_device)->real_device;
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_dev->set_next_ktime(1000000, real_dev);
	hard_local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(rust_helper_proxy_set);

int rust_helper_proxy_set_next_ktime(ktime_t expires,
				struct clock_event_device *dev)
{
	struct clock_event_device *real_dev = container_of(dev, struct clock_proxy_device, proxy_device)->real_device;
	unsigned long flags;
	int ret;

	flags = hard_local_irq_save();
	ret = real_dev->set_next_ktime(expires, real_dev);
	hard_local_irq_restore(flags);

	return ret;
}
EXPORT_SYMBOL_GPL(rust_helper_proxy_set_next_ktime);

unsigned int rust_helper_hard_local_irq_save(void) {
	return hard_local_irq_save();
}
EXPORT_SYMBOL_GPL(rust_helper_hard_local_irq_save);

void rust_helper_hard_local_irq_restore(unsigned int flags) {
	return hard_local_irq_restore(flags);
}
EXPORT_SYMBOL_GPL(rust_helper_hard_local_irq_restore);

void rust_helper_tick_notify_proxy(void)
{
	tick_notify_proxy();
}
EXPORT_SYMBOL_GPL(rust_helper_tick_notify_proxy);

unsigned long rust_helper_IRQF_OOB(void) {
	return IRQF_OOB;
}
EXPORT_SYMBOL_GPL(rust_helper_IRQF_OOB);

void rust_helper_dovetail_send_mayday(struct task_struct *castaway){
	dovetail_send_mayday(castaway);
}
EXPORT_SYMBOL_GPL(rust_helper_dovetail_send_mayday);

struct oob_thread_state *rust_helper_dovetail_current_state(void) {
	return dovetail_current_state();
}
EXPORT_SYMBOL_GPL(rust_helper_dovetail_current_state);

void rust_helper_dovetail_leave_oob(void) {
	dovetail_leave_oob();
}
EXPORT_SYMBOL_GPL(rust_helper_dovetail_leave_oob);

void rust_helper_dovetail_request_ucall(struct task_struct *task) {
	dovetail_request_ucall(task);
}
EXPORT_SYMBOL_GPL(rust_helper_dovetail_request_ucall);

struct oob_mm_state* rust_helper_dovetail_mm_state(void) {
	return dovetail_mm_state();
}
EXPORT_SYMBOL_GPL(rust_helper_dovetail_mm_state);