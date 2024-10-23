// SPDX-License-Identifier: GPL-2.0

//! A condition variable.
//!
//! This module allows Rust code to use the kernel's [`struct wait_queue_head`] as a condition
//! variable.

#[cfg(not(CONFIG_RROS))]
use super::{lock::Backend, lock::Guard, LockClassKey};
use crate::{bindings, init::PinInit, pin_init, str::CStr, types::Opaque};
use core::marker::PhantomPinned;
use core::pin::Pin;
use macros::pin_data;

#[cfg(CONFIG_RROS)]
use crate::sync::guard::{Guard, Lock};
#[cfg(CONFIG_RROS)]
use crate::sync::lock::NeedsLockClass;
#[cfg(CONFIG_RROS)]
use crate::task::Task;

/// Creates a [`CondVar`] initialiser with the given name and a newly-created lock class.
#[cfg(not(CONFIG_RROS))]
#[macro_export]
macro_rules! new_condvar {
    ($($name:literal)?) => {
        $crate::sync::CondVar::new($crate::optional_name!($($name)?), $crate::static_lock_class!())
    };
}

/// A conditional variable.
///
/// Exposes the kernel's [`struct wait_queue_head`] as a condition variable. It allows the caller to
/// atomically release the given lock and go to sleep. It reacquires the lock when it wakes up. And
/// it wakes up when notified by another thread (via [`CondVar::notify_one`] or
/// [`CondVar::notify_all`]) or because the thread received a signal. It may also wake up
/// spuriously.
///
/// Instances of [`CondVar`] need a lock class and to be pinned. The recommended way to create such
/// instances is with the [`pin_init`](crate::pin_init) and [`new_condvar`] macros.
///
/// # Examples
///
/// The following is an example of using a condvar with a mutex:
///
/// ```
/// use kernel::sync::{CondVar, Mutex};
/// use kernel::{new_condvar, new_mutex};
///
/// #[pin_data]
/// pub struct Example {
///     #[pin]
///     value: Mutex<u32>,
///
///     #[pin]
///     value_changed: CondVar,
/// }
///
/// /// Waits for `e.value` to become `v`.
/// fn wait_for_value(e: &Example, v: u32) {
///     let mut guard = e.value.lock();
///     while *guard != v {
///         e.value_changed.wait_uninterruptible(&mut guard);
///     }
/// }
///
/// /// Increments `e.value` and notifies all potential waiters.
/// fn increment(e: &Example) {
///     *e.value.lock() += 1;
///     e.value_changed.notify_all();
/// }
///
/// /// Allocates a new boxed `Example`.
/// fn new_example() -> Result<Pin<Box<Example>>> {
///     Box::pin_init(pin_init!(Example {
///         value <- new_mutex!(0),
///         value_changed <- new_condvar!(),
///     }))
/// }
/// ```
///
/// [`struct wait_queue_head`]: ../../../include/linux/wait.h
#[cfg(not(CONFIG_RROS))]
#[pin_data]
pub struct CondVar {
    #[pin]
    pub(crate) wait_list: Opaque<bindings::wait_queue_head>,

    /// A condvar needs to be pinned because it contains a [`struct list_head`] that is
    /// self-referential, so it cannot be safely moved once it is initialised.
    #[pin]
    _pin: PhantomPinned,
}

// SAFETY: `CondVar` only uses a `struct wait_queue_head`, which is safe to use on any thread.
#[cfg(not(CONFIG_RROS))]
#[allow(clippy::non_send_fields_in_send_ty)]
unsafe impl Send for CondVar {}

// SAFETY: `CondVar` only uses a `struct wait_queue_head`, which is safe to use on multiple threads
// concurrently.
#[cfg(not(CONFIG_RROS))]
unsafe impl Sync for CondVar {}

#[cfg(not(CONFIG_RROS))]
impl CondVar {
    /// Constructs a new condvar initialiser.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(name: &'static CStr, key: &'static LockClassKey) -> impl PinInit<Self> {
        pin_init!(Self {
            _pin: PhantomPinned,
            // SAFETY: `slot` is valid while the closure is called and both `name` and `key` have
            // static lifetimes so they live indefinitely.
            wait_list <- Opaque::ffi_init(|slot| unsafe {
                bindings::__init_waitqueue_head(slot, name.as_char_ptr(), key.as_ptr())
            }),
        })
    }

    fn wait_internal<T: ?Sized, B: Backend>(&self, wait_state: u32, guard: &mut Guard<'_, T, B>) {
        let wait = Opaque::<bindings::wait_queue_entry>::uninit();

        // SAFETY: `wait` points to valid memory.
        unsafe { bindings::init_wait(wait.get()) };

        // SAFETY: Both `wait` and `wait_list` point to valid memory.
        unsafe {
            bindings::prepare_to_wait_exclusive(self.wait_list.get(), wait.get(), wait_state as _)
        };

        // SAFETY: No arguments, switches to another thread.
        guard.do_unlocked(|| unsafe { bindings::schedule() });

        // SAFETY: Both `wait` and `wait_list` point to valid memory.
        unsafe { bindings::finish_wait(self.wait_list.get(), wait.get()) };
    }

    /// Releases the lock and waits for a notification in interruptible mode.
    ///
    /// Atomically releases the given lock (whose ownership is proven by the guard) and puts the
    /// thread to sleep, reacquiring the lock on wake up. It wakes up when notified by
    /// [`CondVar::notify_one`] or [`CondVar::notify_all`], or when the thread receives a signal.
    /// It may also wake up spuriously.
    ///
    /// Returns whether there is a signal pending.
    #[must_use = "wait returns if a signal is pending, so the caller must check the return value"]
    pub fn wait<T: ?Sized, B: Backend>(&self, guard: &mut Guard<'_, T, B>) -> bool {
        self.wait_internal(bindings::TASK_INTERRUPTIBLE, guard);
        crate::current!().signal_pending()
    }

    /// Releases the lock and waits for a notification in uninterruptible mode.
    ///
    /// Similar to [`CondVar::wait`], except that the wait is not interruptible. That is, the
    /// thread won't wake up due to signals. It may, however, wake up supirously.
    pub fn wait_uninterruptible<T: ?Sized, B: Backend>(&self, guard: &mut Guard<'_, T, B>) {
        self.wait_internal(bindings::TASK_UNINTERRUPTIBLE, guard)
    }

    /// Calls the kernel function to notify the appropriate number of threads with the given flags.
    fn notify(&self, count: i32, flags: u32) {
        // SAFETY: `wait_list` points to valid memory.
        unsafe {
            bindings::__wake_up(
                self.wait_list.get(),
                bindings::TASK_NORMAL,
                count,
                flags as _,
            )
        };
    }

    /// Wakes a single waiter up, if any.
    ///
    /// This is not 'sticky' in the sense that if no thread is waiting, the notification is lost
    /// completely (as opposed to automatically waking up the next waiter).
    pub fn notify_one(&self) {
        self.notify(1, 0);
    }

    /// Wakes all waiters up, if any.
    ///
    /// This is not 'sticky' in the sense that if no thread is waiting, the notification is lost
    /// completely (as opposed to automatically waking up the next waiter).
    pub fn notify_all(&self) {
        self.notify(0, 0);
    }
}

extern "C" {
    fn rust_helper_init_wait(wq: *mut bindings::wait_queue_entry);
}

/// Safely initialises a [`CondVar`] with the given name, generating a new lock class.
#[macro_export]
macro_rules! condvar_init {
    ($condvar:expr, $name:literal) => {
        $crate::init_with_lockdep!($condvar, $name)
    };
}

// TODO: `bindgen` is not generating this constant. Figure out why.
const POLLFREE: u32 = 0x4000;

/// Exposes the kernel's [`struct wait_queue_head`] as a condition variable. It allows the caller to
/// atomically release the given lock and go to sleep. It reacquires the lock when it wakes up. And
/// it wakes up when notified by another thread (via [`CondVar::notify_one`] or
/// [`CondVar::notify_all`]) or because the thread received a signal.
///
/// [`struct wait_queue_head`]: ../../../include/linux/wait.h
pub struct CondVar {
    pub(crate) wait_list: Opaque<bindings::wait_queue_head>,

    /// A condvar needs to be pinned because it contains a [`struct list_head`] that is
    /// self-referential, so it cannot be safely moved once it is initialised.
    _pin: PhantomPinned,
}

// SAFETY: `CondVar` only uses a `struct wait_queue_head`, which is safe to use on any thread.
unsafe impl Send for CondVar {}

// SAFETY: `CondVar` only uses a `struct wait_queue_head`, which is safe to use on multiple threads
// concurrently.
unsafe impl Sync for CondVar {}

impl CondVar {
    /// Constructs a new conditional variable.
    ///
    /// # Safety
    ///
    /// The caller must call `CondVar::init` before using the conditional variable.
    pub const unsafe fn new() -> Self {
        Self {
            wait_list: Opaque::uninit(),
            _pin: PhantomPinned,
        }
    }

    /// Atomically releases the given lock (whose ownership is proven by the guard) and puts the
    /// thread to sleep. It wakes up when notified by [`CondVar::notify_one`] or
    /// [`CondVar::notify_all`], or when the thread receives a signal.
    ///
    /// Returns whether there is a signal pending.
    #[must_use = "wait returns if a signal is pending, so the caller must check the return value"]
    pub fn wait<L: Lock>(&self, guard: &mut Guard<'_, L>) -> bool {
        let lock = guard.lock;
        let wait = Opaque::<bindings::wait_queue_entry>::uninit();

        // SAFETY: `wait` points to valid memory.
        unsafe { rust_helper_init_wait(wait.get()) };

        // SAFETY: Both `wait` and `wait_list` point to valid memory.
        unsafe {
            bindings::prepare_to_wait_exclusive(
                self.wait_list.get(),
                wait.get(),
                bindings::TASK_INTERRUPTIBLE as _,
            )
        };

        // SAFETY: The guard is evidence that the caller owns the lock.
        unsafe { lock.unlock() };

        // SAFETY: No arguments, switches to another thread.
        unsafe { bindings::schedule() };

        lock.lock_noguard();

        // SAFETY: Both `wait` and `wait_list` point to valid memory.
        unsafe { bindings::finish_wait(self.wait_list.get(), wait.get()) };

        unsafe { Task::current().signal_pending() }
    }

    /// Calls the kernel function to notify the appropriate number of threads with the given flags.
    fn notify(&self, count: i32, flags: u32) {
        // SAFETY: `wait_list` points to valid memory.
        unsafe {
            bindings::__wake_up(
                self.wait_list.get(),
                bindings::TASK_NORMAL,
                count,
                flags as _,
            )
        };
    }

    /// Wakes a single waiter up, if any. This is not 'sticky' in the sense that if no thread is
    /// waiting, the notification is lost completely (as opposed to automatically waking up the
    /// next waiter).
    pub fn notify_one(&self) {
        self.notify(1, 0);
    }

    /// Wakes all waiters up, if any. This is not 'sticky' in the sense that if no thread is
    /// waiting, the notification is lost completely (as opposed to automatically waking up the
    /// next waiter).
    pub fn notify_all(&self) {
        self.notify(0, 0);
    }

    /// Wakes all waiters up. If they were added by `epoll`, they are also removed from the list of
    /// waiters. This is useful when cleaning up a condition variable that may be waited on by
    /// threads that use `epoll`.
    pub fn free_waiters(&self) {
        self.notify(1, bindings::POLLHUP | POLLFREE);
    }
}

impl NeedsLockClass for CondVar {
    unsafe fn init(self: Pin<&mut Self>, name: &'static CStr, key: *mut bindings::lock_class_key) {
        unsafe { bindings::__init_waitqueue_head(self.wait_list.get(), name.as_char_ptr(), key) };
    }
}
