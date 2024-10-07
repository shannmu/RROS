// SPDX-License-Identifier: GPL-2.0

//! capability
//!
//! C header: [`include/linux/capability.h`](../../../../include/linux/capability.h)

use crate::bindings;

extern "C" {
    fn rust_helper_current_cap() -> bindings::kernel_cap_t;
    fn rust_helper_cap_raised(c: bindings::kernel_cap_t, f: i32) -> i32;
    fn rust_helper_cap_raise(c: *mut bindings::kernel_cap_t, flag: i32);
}

/// Check whether the current process has permissions.
#[inline]
#[cfg(CONFIG_MULTIUSER)]
pub fn capable(cap: i32) -> bool {
    unsafe { bindings::capable(cap) }
}

/// Check whether the current process has permissions.
#[inline]
#[cfg(not(CONFIG_MULTIUSER))]
pub fn capable(_cap: i32) -> bool {
    true
}

/// A wrapper for [`kernel_cap_t`]
#[repr(transparent)]
pub struct KernelCapStruct {
    kernel_cap_t: bindings::kernel_cap_t,
}

impl KernelCapStruct {
    /// Constructs a new struct.
    pub fn new() -> KernelCapStruct {
        KernelCapStruct {
            kernel_cap_t: bindings::kernel_cap_t { val: 0 },
        }
    }

    /// Get current kernel_cap_t.
    pub fn current_cap() -> Self {
        unsafe {
            Self {
                kernel_cap_t: rust_helper_current_cap(),
            }
        }
    }

    /// Check the permission.
    pub fn cap_raise(&mut self, flag: i32) {
        unsafe {
            rust_helper_cap_raise(
                &mut self.kernel_cap_t as *mut bindings::kernel_cap_t,
                flag,
            );
        }
    }

    /// Check the permission.
    pub fn cap_raised(c: KernelCapStruct, flag: i32) -> i32 {
        unsafe { rust_helper_cap_raised(c.kernel_cap_t, flag) }
    }
}
