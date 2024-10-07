// SPDX-License-Identifier: GPL-2.0

//! Synchronisation primitives.
//!
//! This module contains the kernel APIs related to synchronisation that have been ported or
//! wrapped for usage by Rust code in the kernel.

use crate::types::Opaque;

mod arc;
mod condvar;
pub mod lock;
mod locked_by;

pub use arc::{Arc, ArcBorrow, UniqueArc, Ref, RefBorrow};
pub use condvar::{new_condvar, CondVar, CondVarTimeoutResult};
pub use lock::mutex::{new_mutex, Mutex, mutex_lock, mutex_unlock};
pub use lock::spinlock::{new_spinlock, SpinLock, HardSpinlock};
pub use locked_by::LockedBy;

use alloc::boxed::Box;
use crate::str::CStr;
use core::pin::Pin;
use crate::{bindings, c_types};

/// Represents a lockdep class. It's a wrapper around C's `lock_class_key`.
#[repr(transparent)]
pub struct LockClassKey(Opaque<bindings::lock_class_key>);

// SAFETY: `bindings::lock_class_key` is designed to be used concurrently from multiple threads and
// provides its own synchronization.
unsafe impl Sync for LockClassKey {}

impl LockClassKey {
    /// Creates a new lock class key.
    pub const fn new() -> Self {
        Self(Opaque::uninit())
    }

    pub(crate) fn as_ptr(&self) -> *mut bindings::lock_class_key {
        self.0.get()
    }
}

/// Defines a new static lock class and returns a pointer to it.
#[doc(hidden)]
#[macro_export]
macro_rules! static_lock_class {
    () => {{
        static CLASS: $crate::sync::LockClassKey = $crate::sync::LockClassKey::new();
        &CLASS
    }};
}

/// Returns the given string, if one is provided, otherwise generates one based on the source code
/// location.
#[doc(hidden)]
#[macro_export]
macro_rules! optional_name {
    () => {
        $crate::c_str!(::core::concat!(::core::file!(), ":", ::core::line!()))
    };
    ($name:literal) => {
        $crate::c_str!($name)
    };
}

extern "C" {
    fn rust_helper_cond_resched() -> c_types::c_int;
}

/// Reschedules the caller's task if needed.
pub fn cond_resched() -> bool {
    // SAFETY: No arguments, reschedules `current` if needed.
    unsafe { rust_helper_cond_resched() != 0 }
}
