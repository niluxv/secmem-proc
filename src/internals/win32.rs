//! Helper functions for interfacing with the windows specific Win32 API, mainly
//! the security base API.
//!
//! Note that Win32 API is not only for 32 bit machines, but also *the* C API of
//! 64 bit windows.

use crate::error::{AllocErr, SysErr};
use alloc::alloc;
use core::alloc::Layout;
use core::ptr::NonNull;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD as Dword;
use winapi::shared::winerror::ERROR_SUCCESS;
use winapi::um::accctrl::SE_OBJECT_TYPE as SeObjectType;
use winapi::um::winnt::{
    ACCESS_ALLOWED_ACE as AccessAllowedAce, ACL as Acl, ACL_REVISION, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_INFORMATION as SecurityInformation,
};
use winapi::um::{aclapi, processthreadsapi as ptapi, securitybaseapi as sbapi};

pub struct SidPtr(*mut c_void);

impl SidPtr {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }

    /// # Safety
    /// Not unsafe in itself to call because functions which take a `SidPtr` are
    /// unsafe, but the returned null-pointer must be used only when a
    /// function allows for a null `SidPtr`.
    fn null() -> Self {
        Self(core::ptr::null_mut())
    }
}

/// # Safety
/// - `acl` has to point to a valid Acl with write access
/// - `sid` has to point to a valid SID structure
///
/// # Errors
/// Errors if
/// - the Acl pointed to by `acl` doesn't have enough space for the Ace
/// - `revision` is not a valid revision
/// - `access_mask` is not a valid access_mask
unsafe fn add_allowed_ace<E: SysErr>(
    acl: *mut Acl,
    revision: Dword,
    access_mask: Dword,
    sid: SidPtr,
) -> Result<(), E> {
    // SAFETY: uphold by caller
    let res = unsafe { sbapi::AddAccessAllowedAce(acl, revision, access_mask, sid.as_ptr()) };
    if res == 0 {
        Err(E::create())
    } else {
        Ok(())
    }
}

/// # Safety
/// - `acl` must be valid for a `acl_len` byte write, Dword aligned (i.e. 4 byte
///   aligned)
/// - `acl_len` must be Dword aligned (i.e. a multiple of 4)
unsafe fn initialize_acl<E: SysErr>(
    acl: *mut Acl,
    acl_len: Dword,
    revision: Dword,
) -> Result<(), E> {
    // SAFETY: uphold by caller
    let res = unsafe { sbapi::InitializeAcl(acl, acl_len, revision) };
    if res == 0 {
        Err(E::create())
    } else {
        Ok(())
    }
}

/// Safety
/// - `handle` must point to a valid object of type `obj_type`
/// - `owner`, `group` must point to valid SIDs depending on `sec_info`
/// - `dacl` and `sacl` must point to valid ACLs depending on `sec_info`
///
/// See <https://docs.microsoft.com/en-us/windows/win32/api/aclapi/nf-aclapi-setsecurityinfo>
/// and <https://docs.microsoft.com/en-us/windows/win32/secauthz/security-information> for more
/// information.
unsafe fn set_security_info<E: SysErr>(
    handle: *mut c_void,
    obj_type: SeObjectType,
    sec_info: SecurityInformation,
    owner: SidPtr,
    group: SidPtr,
    dacl: *mut Acl,
    sacl: *mut Acl,
) -> Result<(), E> {
    let res = unsafe {
        aclapi::SetSecurityInfo(
            handle,
            obj_type,
            sec_info,
            owner.as_ptr(),
            group.as_ptr(),
            dacl,
            sacl,
        )
    };
    if res == ERROR_SUCCESS {
        Ok(())
    } else {
        // standard library also converts Dword winapi errors into `i32` using `as`
        Err(E::from_code(res as i32))
    }
}

/// Creates pseudo-handle to the current process. Needs not be closed.
pub unsafe fn get_process_handle() -> *mut c_void {
    // calling `GetCurrentProcess` just returns a constant, is safe and cannot fail
    unsafe { ptapi::GetCurrentProcess() }
}

pub struct AclBox {
    // SAFETY INVARIANT: must be 4 byte (Dword) aligned, valid for `size` byte write
    ptr: NonNull<Acl>,
    // SAFETY INVARIANT: must be a multiple of 4, immutable
    size: Dword,
}

impl Drop for AclBox {
    fn drop(&mut self) {
        // SAFETY: align is 4 so power of 2; size is multiple of align so rounding
        // doesn't overflow
        let layout = unsafe { Layout::from_size_align_unchecked(self.size as usize, 4) };
        // SAFETY: `AclBox` can only be created through `Self::alloc` so `self.ptr`
        // points to a memory allocation of `self.size` bytes allocated through
        // the global allocator SAFETY: `layout` is identical to the one in
        // `Self::alloc` since `self.size` hasn't changed
        unsafe { alloc::dealloc(self.ptr.as_ptr().cast::<u8>(), layout) }
    }
}

impl AclBox {
    /// Create allocated and initialized empty ACL.
    ///
    /// # Safety
    /// `size` has to be non-zero and a multiple of 4.
    ///
    /// # Errors
    /// Errors when system is out of memory, or when `size` doesn't fit an empty
    /// ACL.
    pub unsafe fn new<E: SysErr + AllocErr>(size: Dword) -> Result<Self, E> {
        let mut allocation = unsafe { Self::alloc(size) }?;
        allocation.initialize()?;
        Ok(allocation)
    }

    /// Create uninitialized ACL of size `size`. This must be initialized before
    /// use.
    ///
    /// # Safety
    /// `size` has to be non-zero and a multiple of 4.
    /// Call `self.initialize` before using the returned `Self`
    unsafe fn alloc<E: AllocErr>(size: Dword) -> Result<Self, E> {
        debug_assert!(size % 4 == 0);
        debug_assert!(size != 0);

        // SAFETY: align is 4 so power of 2; size is multiple of align so rounding
        // doesn't overflow
        let layout = unsafe { Layout::from_size_align_unchecked(size as usize, 4) };
        // SAFETY: `layout` has non-zero size since `size != 0`
        let ptr = unsafe { alloc::alloc(layout) }.cast::<Acl>();
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr, size }),
            None => Err(E::alloc_err()),
        }
    }

    /// Initialize uninitialized ACL.
    fn initialize<E: SysErr>(&mut self) -> Result<(), E> {
        // SAFETY: `self.ptr` is valid for `self.size` byte writes, both are 4 byte
        // aligned by struct safety invariants
        unsafe { initialize_acl(self.ptr.as_ptr(), self.size, ACL_REVISION.into()) }
    }

    /// Add allowed ACE to the ACL. `access_mask` must be a valid access mask.
    ///
    /// # Safety
    /// - `sid` must point to a valid SID.
    /// - `self` must be large enough to add this ACE.
    pub unsafe fn add_allowed_ace<E: SysErr>(
        &mut self,
        access_mask: Dword,
        sid: SidPtr,
    ) -> Result<(), E> {
        // SAFETY: `self.ptr` points to a valid ACL since it must have been created by
        // `Self::new` which properly initializes the ACL
        unsafe { add_allowed_ace(self.ptr.as_ptr(), ACL_REVISION.into(), access_mask, sid) }
    }

    /// Set this DACL to the object pointed to by `handle` of type `obj_type`.
    /// The DACL is set protected, meaning it doesn't inherit ACEs.
    ///
    /// # Safety
    /// `handle` must point to a valid object of type `obj_type`.
    pub unsafe fn set_protected<E: SysErr>(
        &self,
        handle: *mut c_void,
        obj_type: SeObjectType,
    ) -> Result<(), E> {
        // change only DACL, do not inherit ACEs
        let sec_info: SecurityInformation =
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
        // SAFETY: the `SidPtr`s and (last) SACL pointer can be null since `sec_info`
        // states that we only modify the DACL
        // SAFETY: `handle` validity is uphold by the caller
        unsafe {
            set_security_info(
                handle,
                obj_type,
                sec_info,
                SidPtr::null(),
                SidPtr::null(),
                self.ptr.as_ptr(),
                core::ptr::null_mut(),
            )
        }
    }
}

/// Helper type to compute the size necessary for an ACL object, aiding creation
/// of an [`AclBox`].
///
/// # Panics
/// Associated methods panic when the size wraps around a `u32`. This should
/// never happen as having an ACL of that size is not realistic (and also such
/// large ACLs cannot be created in Windows).
#[derive(Clone, Copy, Debug)]
pub struct AclSize(Dword);

impl AclSize {
    /// Returns the size as a `u32`.
    ///
    /// # Panics
    /// Panics when rounding the size up to a multiple of 4 wraps a `u32`.
    pub fn get_size(self) -> u32 {
        // round to a multiple of 4
        self.0.checked_add(3).unwrap() & !3
    }

    /// Allocate an (empty, but initialised) [`AclBox`] with this size.
    pub fn allocate<E: SysErr + AllocErr>(self) -> Result<AclBox, E> {
        // SAFETY: `self.get_size()` is non-zero and a multiple of 4
        // SAFETY: `self.get_size()` large enough to hold an empty ACL, as `Self::new`
        // enforces this and is the only constructor, and wrapping always panics
        unsafe { AclBox::new(self.get_size()) }
    }

    /// Create [`AclSize`] for an empty ACL.
    pub fn new() -> Self {
        Self(core::mem::size_of::<Acl>() as Dword)
    }

    /// Add access allowed ace (size). `sid_size` should be the size of the used
    /// sid.
    ///
    /// # Panics
    /// Panics when adding the ACE size wraps.
    pub fn add_allowed_ace(&mut self, sid_size: u32) {
        // add size of ACE minus the sidstart field (Dword -> 4 bytes)
        self.0 = self
            .0
            .checked_add(core::mem::size_of::<AccessAllowedAce>() as u32 - 4)
            .unwrap();
        // add size of sid
        self.0 = self.0.checked_add(sid_size).unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestSysErr;
    use winapi::um::accctrl::SE_KERNEL_OBJECT;

    #[test]
    fn test_create_drop_aclbox() {
        let size = AclSize::new();
        let _acl: AclBox = size.allocate::<TestSysErr>().expect("could not create ACL");
    }

    #[test]
    fn test_set_empty_acl() {
        let size = AclSize::new();
        let acl: AclBox = size.allocate::<TestSysErr>().expect("could not create ACL");
        // SAFETY: `get_process_handle()` yields a valid handle to this process
        unsafe { acl.set_protected::<TestSysErr>(get_process_handle(), SE_KERNEL_OBJECT) }
            .expect("could not set ACL");
    }
}
