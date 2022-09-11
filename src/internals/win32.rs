//! Helper functions for interfacing with the windows specific Win32 API, mainly
//! the security base API.
//!
//! Note that Win32 API is not only for 32 bit machines, but also *the* C API of
//! 64 bit windows.

use crate::error::{AllocErr, SysErr};
use alloc::alloc;
use core::alloc::Layout;
use core::ffi::c_void;
use core::ptr::NonNull;

mod win {
    // import functions
    pub(super) use windows::Win32::Foundation::CloseHandle;
    pub(super) use windows::Win32::Security::Authorization::SetSecurityInfo;
    pub(super) use windows::Win32::Security::{
        AddAccessAllowedAce, GetLengthSid, GetTokenInformation, InitializeAcl, IsValidSid,
    };
    pub(super) use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    // import structures
    pub(super) use windows::Win32::Foundation::{HANDLE, PSID, WIN32_ERROR};
    pub(super) use windows::Win32::Security::Authorization::SE_OBJECT_TYPE;
    pub(super) use windows::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_REVISION, ACL, OBJECT_SECURITY_INFORMATION, TOKEN_ACCESS_MASK,
        TOKEN_USER,
    };
    pub(super) use windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

    // import constants
    pub(super) use windows::Win32::Foundation::ERROR_SUCCESS;
    pub(super) use windows::Win32::Security::{
        TokenUser, ACL_REVISION, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };
}

/// Pointer to a SID.
#[derive(Copy, Clone, Debug)]
pub struct SidPtr(win::PSID);

impl From<SidPtr> for win::PSID {
    fn from(ptr: SidPtr) -> Self {
        ptr.0
    }
}

impl From<&SidPtr> for win::PSID {
    fn from(ptr: &SidPtr) -> Self {
        (*ptr).0
    }
}

impl SidPtr {
    //     /// Get raw pointer (for FFI).
    //     #[must_use]
    //     fn as_ptr(&self) -> *mut c_void {
    //         self.0
    //     }

    /// # Safety
    /// Not unsafe in itself to call because functions which take a `SidPtr` are
    /// unsafe, but the returned null-pointer must be used only when a
    /// function allows for a null `SidPtr`.
    #[must_use]
    fn null() -> Self {
        Self(win::PSID(core::ptr::null_mut()))
    }

    /// Checks whether `self` points to a valid SID.
    #[must_use]
    fn is_valid(&self) -> bool {
        if self.0.is_invalid() {
            return false;
        }
        // SAFETY: `IsValidSid` requires non-null `PSID`; this is handled by the
        // `is_invalid` check above
        unsafe { win::IsValidSid(self) }.as_bool()
    }

    /// Returns the length of the SID that `self` points to.
    ///
    /// # Safety
    /// Requires `self` to point to a valid SID.
    #[must_use]
    pub unsafe fn len(&self) -> u32 {
        debug_assert!(self.is_valid());
        unsafe { win::GetLengthSid(self) }
    }
}

/// A pointer to a SID valid for lifetime `'a`.
#[allow(clippy::len_without_is_empty)]
#[derive(Copy, Clone, Debug)]
pub struct SidRef<'a> {
    ptr: SidPtr,
    lifetime: core::marker::PhantomData<&'a [u8]>,
}

impl<'a> SidRef<'a> {
    /// Get the raw pointer to the SID, for FFI.
    #[must_use]
    fn as_ptr(&self) -> SidPtr {
        self.ptr
    }

    /// Cast SID pointer into SID reference.
    ///
    /// # Safety
    /// `ptr` must point to a valid SID for at least the lifetime `'a`.
    #[must_use]
    unsafe fn from_ptr(ptr: SidPtr) -> Self {
        debug_assert!(ptr.is_valid());
        Self {
            ptr,
            lifetime: core::marker::PhantomData,
        }
    }

    /// Returns the length of the SID that `self` points to.
    #[must_use]
    pub fn len(&self) -> u32 {
        // SAFETY: `SidRef` must always point to a valid SID
        unsafe { self.ptr.len() }
    }

    /// Checks whether `self` points to a valid SID.
    #[cfg(test)]
    #[must_use]
    fn is_valid(&self) -> bool {
        self.ptr.is_valid()
    }
}

/// Handle to an access token.
pub struct AccessToken(win::HANDLE);

impl Drop for AccessToken {
    fn drop(&mut self) {
        // SAFETY: safe since `self.0` must be an open (access token) handle
        let res = unsafe { win::CloseHandle(self.0) };
        res.unwrap()
    }
}

impl AccessToken {
    /// Given a process handle, this function returns a pointer to the process
    /// token of this process.
    ///
    /// # Safety
    /// `handle` must be a valid handle to a process.
    pub unsafe fn open_process_token<E: SysErr>(
        handle: win::HANDLE,
        access: win::TOKEN_ACCESS_MASK,
    ) -> Result<Self, E> {
        let mut token_handle = win::HANDLE(0);
        let res =
            unsafe { win::OpenProcessToken(handle, access, &mut token_handle as *mut win::HANDLE) };
        if res.as_bool() {
            Ok(AccessToken(token_handle))
        } else {
            Err(E::create())
        }
    }

    /// Given a token handle, this function returns the token user structure.
    pub fn get_token_user<E: SysErr + AllocErr>(&self) -> Result<TokenUserBox, E> {
        // Get the required length of the buffer
        let mut length: u32 = 0;
        let _ = unsafe {
            win::GetTokenInformation(
                self.0,
                win::TokenUser,
                core::ptr::null_mut() as *mut c_void,
                0,
                &mut length as *mut u32,
            )
        };

        // Allocate buffer of this length
        // SAFETY: 4 is power of 2, size is always sufficiently small
        let layout = unsafe { Layout::from_size_align_unchecked(length as usize, 4) };
        let ptr = unsafe { alloc::alloc(layout) };
        let buf_ptr = match NonNull::new(ptr) {
            Some(ptr) => ptr,
            None => return Err(E::alloc_err()),
        };

        let token_user = TokenUserBox {
            ptr: buf_ptr,
            size: length,
        };

        // Write token user into the allocated buffer
        let res = unsafe {
            win::GetTokenInformation(
                self.0,
                win::TokenUser,
                ptr.cast::<c_void>(),
                length,
                &mut length as *mut u32,
            )
        };

        if res.as_bool() {
            Ok(token_user)
        } else {
            Err(E::create())
        }
    }
}

/// Heap allocated structure containing a token user.
pub struct TokenUserBox {
    ptr: NonNull<u8>,
    size: u32,
}

impl Drop for TokenUserBox {
    fn drop(&mut self) {
        // SAFETY: 4 is power of 2, size is always sufficiently small
        let layout = unsafe { Layout::from_size_align_unchecked(self.size as usize, 4) };
        unsafe { alloc::dealloc(self.ptr.as_ptr(), layout) };
    }
}

impl TokenUserBox {
    /// Given a token handle, this function returns the token user structure.
    pub fn from_token<E: SysErr + AllocErr>(token: &AccessToken) -> Result<Self, E> {
        token.get_token_user()
    }

    /// Given a token user, this function returns a reference to the user SID.
    #[must_use]
    pub fn sid<'a>(&'a self) -> SidRef<'a> {
        let ptr: *mut win::TOKEN_USER = self.ptr.as_ptr().cast();
        // SAFETY: all functions creating `Self` guarantee that the buffer is
        // initialised with a `win::TOKEN_USER` structure at the start of the memory
        // range
        let tokenuser_ref: &'a win::TOKEN_USER = unsafe { ptr.as_mut().unwrap() };
        let sidptr = SidPtr(tokenuser_ref.User.Sid);
        // SAFETY: `sidptr` points to a SID in the `TokenUserBox` allocation, so the SID
        // pointer is valid at least for the borrow lifetime of `self`
        unsafe { SidRef::<'a>::from_ptr(sidptr) }
    }
}

/// Add access allowed ACE to the ACL pointed to by `acl`.
///
/// # Safety
/// - `acl` has to point to a valid ACL with write access
///
/// # Errors
/// Errors if
/// - the ACL pointed to by `acl` doesn't have enough space for the Ace
/// - `revision` is not a valid revision
/// - `access_mask` is not a valid access_mask
unsafe fn add_allowed_ace<E: SysErr>(
    acl: *mut win::ACL,
    revision: win::ACE_REVISION,
    access_mask: win::PROCESS_ACCESS_RIGHTS,
    sid: SidRef<'_>,
) -> Result<(), E> {
    // SAFETY: uphold by caller
    let res = unsafe { win::AddAccessAllowedAce(acl, revision.0, access_mask.0, sid.as_ptr()) };
    if res.as_bool() {
        Ok(())
    } else {
        Err(E::create())
    }
}

/// # Safety
/// - `acl` must be valid for a `acl_len` byte write, 4 byte aligned
/// - `acl_len` must be a multiple of 4
unsafe fn initialize_acl<E: SysErr>(
    acl: *mut win::ACL,
    acl_len: u32,
    revision: win::ACE_REVISION,
) -> Result<(), E> {
    // SAFETY: uphold by caller
    let res = unsafe { win::InitializeAcl(acl, acl_len, revision.0) };
    if res.as_bool() {
        Ok(())
    } else {
        Err(E::create())
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
    handle: win::HANDLE,
    obj_type: win::SE_OBJECT_TYPE,
    sec_info: win::OBJECT_SECURITY_INFORMATION,
    owner: SidPtr,
    group: SidPtr,
    dacl: *const win::ACL,
    sacl: *const win::ACL,
) -> Result<(), E> {
    let res =
        unsafe { win::SetSecurityInfo(handle, obj_type, sec_info.0, owner, group, dacl, sacl) };
    if win::WIN32_ERROR(res) == win::ERROR_SUCCESS {
        Ok(())
    } else {
        // standard library also converts `u32` winapi errors into `i32` using `as`
        Err(E::from_code(res as i32))
    }
}

/// Creates pseudo-handle to the current process. Needs not be closed.
#[must_use]
pub unsafe fn get_process_handle() -> win::HANDLE {
    // calling `GetCurrentProcess` just returns a constant, is safe and cannot fail
    unsafe { win::GetCurrentProcess() }
}

/// Heap allocated ACL.
pub struct AclBox {
    // SAFETY INVARIANT: must be 4 byte (`u32`) aligned, valid for `size` byte write
    ptr: NonNull<win::ACL>,
    // SAFETY INVARIANT: must be a multiple of 4, immutable
    size: u32,
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
    pub unsafe fn new<E: SysErr + AllocErr>(size: u32) -> Result<Self, E> {
        let mut allocation = unsafe { Self::alloc(size) }?;
        allocation.initialize()?;
        Ok(allocation)
    }

    /// Create uninitialized ACL of size `size`. This must be initialized before
    /// use.
    ///
    /// # Safety
    /// `size` has to be non-zero and a multiple of 4.
    /// Call `self.initialize()` before using the returned `Self`
    unsafe fn alloc<E: AllocErr>(size: u32) -> Result<Self, E> {
        debug_assert!(size % 4 == 0);
        debug_assert!(size != 0);

        // SAFETY: align is 4 so power of 2; size is multiple of align so rounding
        // doesn't overflow
        let layout = unsafe { Layout::from_size_align_unchecked(size as usize, 4) };
        // SAFETY: `layout` has non-zero size since `size != 0`
        let ptr = unsafe { alloc::alloc(layout) }.cast::<win::ACL>();
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr, size }),
            None => Err(E::alloc_err()),
        }
    }

    /// Initialize uninitialized ACL.
    fn initialize<E: SysErr>(&mut self) -> Result<(), E> {
        // SAFETY: `self.ptr` is valid for `self.size` byte writes, both are 4 byte
        // aligned by struct safety invariants
        unsafe { initialize_acl(self.ptr.as_ptr(), self.size, win::ACL_REVISION.into()) }
    }

    /// Add allowed ACE to the ACL. `access_mask` must be a valid access mask.
    ///
    /// # Safety
    /// - `self` must be large enough to add this ACE.
    pub unsafe fn add_allowed_ace<E: SysErr>(
        &mut self,
        access_mask: win::PROCESS_ACCESS_RIGHTS,
        sid: SidRef<'_>,
    ) -> Result<(), E> {
        // SAFETY: `self.ptr` points to a valid ACL since it must have been created by
        // `Self::new` which properly initializes the ACL
        unsafe {
            add_allowed_ace(
                self.ptr.as_ptr(),
                win::ACL_REVISION.into(),
                access_mask,
                sid,
            )
        }
    }

    /// Set this DACL to the object pointed to by `handle` of type `obj_type`.
    /// The DACL is set protected, meaning it doesn't inherit ACEs.
    ///
    /// # Safety
    /// `handle` must point to a valid object of type `obj_type`.
    pub unsafe fn set_protected<E: SysErr>(
        &self,
        handle: win::HANDLE,
        obj_type: win::SE_OBJECT_TYPE,
    ) -> Result<(), E> {
        // change only DACL, do not inherit ACEs
        let sec_info: win::OBJECT_SECURITY_INFORMATION =
            win::DACL_SECURITY_INFORMATION | win::PROTECTED_DACL_SECURITY_INFORMATION;
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
pub struct AclSize(u32);

impl AclSize {
    /// Returns the size as a `u32`.
    ///
    /// # Panics
    /// Panics when rounding the size up to a multiple of 4 wraps a `u32`.
    #[must_use]
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
    #[must_use]
    pub fn new() -> Self {
        #[allow(clippy::cast_possible_truncation)]
        let empty_size = core::mem::size_of::<win::ACL>() as u32;
        Self(empty_size)
    }

    /// Add access allowed ace (size). `sid_size` should be the size of the used
    /// sid.
    ///
    /// # Panics
    /// Panics when adding the ACE size wraps.
    pub fn add_allowed_ace(&mut self, sid_size: u32) {
        #[allow(clippy::cast_possible_truncation)]
        let ace_header_size = core::mem::size_of::<win::ACCESS_ALLOWED_ACE>() as u32;

        // add size of ACE minus the sidstart field (u32 -> 4 bytes)
        self.0 = self.0.checked_add(ace_header_size - 4).unwrap();
        // add size of sid
        self.0 = self.0.checked_add(sid_size).unwrap();
    }
}

impl Default for AclSize {
    #[must_use]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestSysErr;
    use windows::Win32::Security::Authorization::SE_KERNEL_OBJECT;
    use windows::Win32::Security::TOKEN_QUERY;
    use windows::Win32::System::Threading::{
        PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
    };

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

    #[test]
    fn test_open_process_token() {
        let _process_tok = unsafe {
            AccessToken::open_process_token::<TestSysErr>(get_process_handle(), TOKEN_QUERY)
        }
        .expect("could not open process token");
    }

    #[test]
    fn test_get_process_user_sid() {
        let process_tok = unsafe {
            AccessToken::open_process_token::<TestSysErr>(get_process_handle(), TOKEN_QUERY)
        }
        .expect("could not open process token");
        let tok_user = process_tok
            .get_token_user::<TestSysErr>()
            .expect("could not retrieve token user");
        let sid = tok_user.sid();
        // It seems the SID remains valid after closing the process token
        core::mem::drop(process_tok);
        assert!(sid.is_valid());
    }

    #[test]
    fn test_aclbox_allowed_ace() {
        let process_tok = unsafe {
            AccessToken::open_process_token::<TestSysErr>(get_process_handle(), TOKEN_QUERY)
        }
        .expect("could not open process token");
        let tok_user = process_tok
            .get_token_user::<TestSysErr>()
            .expect("could not retrieve token user");
        let sid = tok_user.sid();
        assert!(sid.is_valid());

        let mut size = AclSize::new();
        size.add_allowed_ace(sid.len());
        let mut acl: AclBox = size.allocate::<TestSysErr>().expect("could not create ACL");
        unsafe {
            acl.add_allowed_ace::<TestSysErr>(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                sid,
            )
        }
        .expect("could not add ACE to ACL");
    }
}
