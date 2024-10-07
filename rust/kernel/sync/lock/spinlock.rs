// SPDX-License-Identifier: GPL-2.0

//! A kernel spinlock.
//!
//! This module allows Rust code to use the kernel's `spinlock_t`.

use crate::{bindings, c_types};

extern "C" {
    #[allow(improper_ctypes)]
    fn rust_helper_spin_lock_init(
        lock: *mut bindings::spinlock_t,
        name: *const c_types::c_char,
        key: *mut bindings::lock_class_key,
    );
    #[allow(dead_code)]
    fn rust_helper_spin_lock(lock: *mut bindings::spinlock);
    #[allow(dead_code)]
    fn rust_helper_spin_unlock(lock: *mut bindings::spinlock);
    fn rust_helper_hard_spin_lock(lock: *mut bindings::raw_spinlock);
    fn rust_helper_hard_spin_unlock(lock: *mut bindings::raw_spinlock);
    fn rust_helper_raw_spin_lock_irqsave(lock: *mut bindings::hard_spinlock_t) -> u64;
    fn rust_helper_raw_spin_unlock_irqrestore(lock: *mut bindings::hard_spinlock_t, flags: u64);
    fn rust_helper_raw_spin_lock_init(lock: *mut bindings::raw_spinlock_t);
    fn rust_helper_raw_spin_lock(lock: *mut bindings::hard_spinlock_t);
    fn rust_helper_raw_spin_unlock(lock: *mut bindings::hard_spinlock_t);
    fn rust_helper_raw_spin_lock_nested(lock: *mut bindings::hard_spinlock_t, depth: u32);
}

/// Creates a [`SpinLock`] initialiser with the given name and a newly-created lock class.
///
/// It uses the name if one is given, otherwise it generates one based on the file name and line
/// number.
#[macro_export]
macro_rules! new_spinlock {
    ($inner:expr $(, $name:literal)? $(,)?) => {
        $crate::sync::SpinLock::new(
            $inner, $crate::optional_name!($($name)?), $crate::static_lock_class!())
    };
}
pub use new_spinlock;

/// A spinlock.
///
/// Exposes the kernel's [`spinlock_t`]. When multiple CPUs attempt to lock the same spinlock, only
/// one at a time is allowed to progress, the others will block (spinning) until the spinlock is
/// unlocked, at which point another CPU will be allowed to make progress.
///
/// Instances of [`SpinLock`] need a lock class and to be pinned. The recommended way to create such
/// instances is with the [`pin_init`](crate::pin_init) and [`new_spinlock`] macros.
///
/// # Examples
///
/// The following example shows how to declare, allocate and initialise a struct (`Example`) that
/// contains an inner struct (`Inner`) that is protected by a spinlock.
///
/// ```
/// use kernel::sync::{new_spinlock, SpinLock};
///
/// struct Inner {
///     a: u32,
///     b: u32,
/// }
///
/// #[pin_data]
/// struct Example {
///     c: u32,
///     #[pin]
///     d: SpinLock<Inner>,
/// }
///
/// impl Example {
///     fn new() -> impl PinInit<Self> {
///         pin_init!(Self {
///             c: 10,
///             d <- new_spinlock!(Inner { a: 20, b: 30 }),
///         })
///     }
/// }
///
/// // Allocate a boxed `Example`.
/// let e = Box::pin_init(Example::new())?;
/// assert_eq!(e.c, 10);
/// assert_eq!(e.d.lock().a, 20);
/// assert_eq!(e.d.lock().b, 30);
/// # Ok::<(), Error>(())
/// ```
///
/// The following example shows how to use interior mutability to modify the contents of a struct
/// protected by a spinlock despite only having a shared reference:
///
/// ```
/// use kernel::sync::SpinLock;
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn example(m: &SpinLock<Example>) {
///     let mut guard = m.lock();
///     guard.a += 10;
///     guard.b += 20;
/// }
/// ```
///
/// [`spinlock_t`]: srctree/include/linux/spinlock.h
pub type SpinLock<T> = super::Lock<T, SpinLockBackend>;

/// A kernel `spinlock_t` lock backend.
pub struct SpinLockBackend;

// SAFETY: The underlying kernel `spinlock_t` object ensures mutual exclusion. `relock` uses the
// default implementation that always calls the same locking method.
unsafe impl super::Backend for SpinLockBackend {
    type State = bindings::spinlock_t;
    type GuardState = ();

    unsafe fn init(
        ptr: *mut Self::State,
        name: *const core::ffi::c_char,
        key: *mut bindings::lock_class_key,
    ) {
        // SAFETY: The safety requirements ensure that `ptr` is valid for writes, and `name` and
        // `key` are valid for read indefinitely.
        unsafe { bindings::__spin_lock_init(ptr, name, key) }
    }

    unsafe fn lock(ptr: *mut Self::State) -> Self::GuardState {
        // SAFETY: The safety requirements of this function ensure that `ptr` points to valid
        // memory, and that it has been initialised before.
        unsafe { bindings::spin_lock(ptr) }
    }

    unsafe fn unlock(ptr: *mut Self::State, _guard_state: &Self::GuardState) {
        // SAFETY: The safety requirements of this function ensure that `ptr` is valid and that the
        // caller is the owner of the spinlock.
        unsafe { bindings::spin_unlock(ptr) }
    }
}

/// A wrapper for [`hard_spinlock_t`].
#[repr(transparent)]
pub struct HardSpinlock {
    lock: bindings::hard_spinlock_t,
}

impl HardSpinlock {
    /// Constructs a new struct.
    pub fn new() -> Self {
        HardSpinlock {
            lock: bindings::hard_spinlock_t {
                rlock: bindings::raw_spinlock {
                    raw_lock: bindings::arch_spinlock_t {
                        __bindgen_anon_1: bindings::qspinlock__bindgen_ty_1 {
                            val: bindings::atomic_t { counter: 0 },
                        },
                    },
                },
                dep_map: bindings::phony_lockdep_map {
                    // wait_type_outer: 0,
                    // wait_type_inner: 0,
                },
            },
        }
    }

    /// Initialize Self.
    pub fn init(&mut self) {
        self.lock = bindings::hard_spinlock_t::default();
        // SAFETY: `self.lock` points to valid memory.
        unsafe {
            rust_helper_raw_spin_lock_init(
                &mut self.lock as *mut bindings::hard_spinlock_t as *mut bindings::raw_spinlock_t,
            );
        }
    }

    /// Call `Linux` `raw_spin_lock_irqsave` to lock.
    pub fn raw_spin_lock_irqsave(&mut self) -> u64 {
        // SAFETY: The caller guarantees that self is initialised. So the pointer is valid.
        unsafe {
            rust_helper_raw_spin_lock_irqsave(&mut self.lock as *mut bindings::hard_spinlock_t)
        }
    }

    /// Call `Linux` `raw_spin_unlock_irqrestore` to unlock.
    pub fn raw_spin_unlock_irqrestore(&mut self, flags: u64) {
        // SAFETY: The caller guarantees that self is initialised. So the pointer is valid.
        unsafe {
            rust_helper_raw_spin_unlock_irqrestore(
                &mut self.lock as *mut bindings::hard_spinlock_t,
                flags,
            );
        }
    }

    /// Call `Linux` `raw_spin_lock` to lock.
    pub fn raw_spin_lock(&mut self) {
        // SAFETY: The caller guarantees that self is initialised. So the pointer is valid.
        unsafe {
            rust_helper_raw_spin_lock(&mut self.lock as *mut bindings::hard_spinlock_t);
        }
    }

    /// Call `Linux` `raw_spin_unlock` to unlock.
    pub fn raw_spin_unlock(&mut self) {
        // SAFETY: The caller guarantees that self is initialised. So the pointer is valid.
        unsafe {
            rust_helper_raw_spin_unlock(&mut self.lock as *mut bindings::hard_spinlock_t);
        }
    }

    /// Call `Linux` `raw_spin_lock_nested` to lock nestly.
    pub fn raw_spin_lock_nested(&mut self, depth: u32) {
        // SAFETY: The caller guarantees that self is initialised. So the pointer is valid.
        unsafe {
            rust_helper_raw_spin_lock_nested(
                &mut self.lock as *mut bindings::hard_spinlock_t,
                depth,
            )
        }
    }
}