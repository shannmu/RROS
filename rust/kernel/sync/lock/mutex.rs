// SPDX-License-Identifier: GPL-2.0

//! A kernel mutex.
//!
//! This module allows Rust code to use the kernel's `struct mutex`.

#[cfg(CONFIG_RROS)]
use super::NeedsLockClass;
#[cfg(CONFIG_RROS)]
use crate::sync::guard::{Guard, Lock};
use crate::{bindings, str::CStr, Opaque};
use core::{cell::UnsafeCell, marker::PhantomPinned, pin::Pin};
/// Creates a [`Mutex`] initialiser with the given name and a newly-created lock class.
///
/// It uses the name if one is given, otherwise it generates one based on the file name and line
/// number.
#[cfg(not(CONFIG_RROS))]
#[macro_export]
macro_rules! new_mutex {
    ($inner:expr $(, $name:literal)? $(,)?) => {
        $crate::sync::Mutex::new(
            $inner, $crate::optional_name!($($name)?), $crate::static_lock_class!())
    };
}

/// A mutual exclusion primitive.
///
/// Exposes the kernel's [`struct mutex`]. When multiple threads attempt to lock the same mutex,
/// only one at a time is allowed to progress, the others will block (sleep) until the mutex is
/// unlocked, at which point another thread will be allowed to wake up and make progress.
///
/// Since it may block, [`Mutex`] needs to be used with care in atomic contexts.
///
/// Instances of [`Mutex`] need a lock class and to be pinned. The recommended way to create such
/// instances is with the [`pin_init`](crate::pin_init) and [`new_mutex`] macros.
///
/// # Examples
///
/// The following example shows how to declare, allocate and initialise a struct (`Example`) that
/// contains an inner struct (`Inner`) that is protected by a mutex.
///
/// ```
/// use kernel::{init::InPlaceInit, init::PinInit, new_mutex, pin_init, sync::Mutex};
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
///     d: Mutex<Inner>,
/// }
///
/// impl Example {
///     fn new() -> impl PinInit<Self> {
///         pin_init!(Self {
///             c: 10,
///             d <- new_mutex!(Inner { a: 20, b: 30 }),
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
/// protected by a mutex despite only having a shared reference:
///
/// ```
/// use kernel::sync::Mutex;
///
/// struct Example {
///     a: u32,
///     b: u32,
/// }
///
/// fn example(m: &Mutex<Example>) {
///     let mut guard = m.lock();
///     guard.a += 10;
///     guard.b += 20;
/// }
/// ```
///
/// [`struct mutex`]: ../../../../include/linux/mutex.h
#[cfg(not(CONFIG_RROS))]
pub type Mutex<T> = super::Lock<T, MutexBackend>;

/// A kernel `struct mutex` lock backend.
#[cfg(not(CONFIG_RROS))]
pub struct MutexBackend;

// SAFETY: The underlying kernel `struct mutex` object ensures mutual exclusion.
#[cfg(not(CONFIG_RROS))]
unsafe impl super::Backend for MutexBackend {
    type State = bindings::mutex;
    type GuardState = ();

    unsafe fn init(
        ptr: *mut Self::State,
        name: *const core::ffi::c_char,
        key: *mut bindings::lock_class_key,
    ) {
        // SAFETY: The safety requirements ensure that `ptr` is valid for writes, and `name` and
        // `key` are valid for read indefinitely.
        unsafe { bindings::__mutex_init(ptr, name, key) }
    }

    unsafe fn lock(ptr: *mut Self::State) -> Self::GuardState {
        // SAFETY: The safety requirements of this function ensure that `ptr` points to valid
        // memory, and that it has been initialised before.
        unsafe { bindings::mutex_lock(ptr) };
    }

    unsafe fn unlock(ptr: *mut Self::State, _guard_state: &Self::GuardState) {
        // SAFETY: The safety requirements of this function ensure that `ptr` is valid and that the
        // caller is the owner of the mutex.
        unsafe { bindings::mutex_unlock(ptr) };
    }
}

/// Safely initialises a [`Mutex`] with the given name, generating a new lock class.
#[cfg(CONFIG_RROS)]
#[macro_export]
macro_rules! mutex_init {
    ($mutex:expr, $name:literal) => {
        $crate::init_with_lockdep!($mutex, $name)
    };
}

/// Exposes the kernel's [`struct mutex`]. When multiple threads attempt to lock the same mutex,
/// only one at a time is allowed to progress, the others will block (sleep) until the mutex is
/// unlocked, at which point another thread will be allowed to wake up and make progress.
///
/// A [`Mutex`] must first be initialised with a call to [`Mutex::init`] before it can be used. The
/// [`mutex_init`] macro is provided to automatically assign a new lock class to a mutex instance.
///
/// Since it may block, [`Mutex`] needs to be used with care in atomic contexts.
///
/// [`struct mutex`]: ../../../include/linux/mutex.h
#[cfg(CONFIG_RROS)]
pub struct Mutex<T: ?Sized> {
    /// The kernel `struct mutex` object.
    mutex: Opaque<bindings::mutex>,

    /// A mutex needs to be pinned because it contains a [`struct list_head`] that is
    /// self-referential, so it cannot be safely moved once it is initialised.
    _pin: PhantomPinned,

    /// The data protected by the mutex.
    data: UnsafeCell<T>,
}

// SAFETY: `Mutex` can be transferred across thread boundaries iff the data it protects can.
#[cfg(CONFIG_RROS)]
unsafe impl<T: ?Sized + Send> Send for Mutex<T> {}

// SAFETY: `Mutex` serialises the interior mutability it provides, so it is `Sync` as long as the
// data it protects is `Send`.
#[cfg(CONFIG_RROS)]
unsafe impl<T: ?Sized + Send> Sync for Mutex<T> {}

#[cfg(CONFIG_RROS)]
impl<T> Mutex<T> {
    /// Constructs a new mutex.
    ///
    /// # Safety
    ///
    /// The caller must call [`Mutex::init`] before using the mutex.
    pub const unsafe fn new(t: T) -> Self {
        Self {
            mutex: Opaque::uninit(),
            data: UnsafeCell::new(t),
            _pin: PhantomPinned,
        }
    }
}

#[cfg(CONFIG_RROS)]
impl<T: ?Sized> Mutex<T> {
    /// Locks the mutex and gives the caller access to the data protected by it. Only one thread at
    /// a time is allowed to access the protected data.
    pub fn lock(&self) -> Guard<'_, Self> {
        self.lock_noguard();
        // SAFETY: The mutex was just acquired.
        unsafe { Guard::new(self) }
    }
}

#[cfg(CONFIG_RROS)]
impl<T: ?Sized> NeedsLockClass for Mutex<T> {
    unsafe fn init(self: Pin<&mut Self>, name: &'static CStr, key: *mut bindings::lock_class_key) {
        unsafe { bindings::__mutex_init(self.mutex.get(), name.as_char_ptr(), key) };
    }
}

#[cfg(CONFIG_RROS)]
extern "C" {
    #[allow(dead_code)]
    fn rust_helper_mutex_lock(mutex: *mut bindings::mutex);
}

#[cfg(CONFIG_RROS)]
impl<T: ?Sized> Lock for Mutex<T> {
    type Inner = T;

    fn lock_noguard(&self) {
        // SAFETY: `mutex` points to valid memory.
        unsafe { bindings::mutex_lock(self.mutex.get()) };
    }

    unsafe fn unlock(&self) {
        unsafe { bindings::mutex_unlock(self.mutex.get()) };
    }

    fn locked_data(&self) -> &UnsafeCell<T> {
        &self.data
    }
}

/// Call `Linux` mutex_lock.
#[cfg(CONFIG_RROS)]
pub fn mutex_lock(lock: *mut bindings::mutex) {
    unsafe {
        bindings::mutex_lock(lock);
    }
}

/// Call `Linux` mutex_unlock.
#[cfg(CONFIG_RROS)]
pub fn mutex_unlock(lock: *mut bindings::mutex) {
    unsafe {
        bindings::mutex_unlock(lock);
    }
}
