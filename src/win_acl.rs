//! Safe Windows DACL API.
//!
//! This API can be used to create and set a custom DACL on Windows, for the
//! case where the default one set by
//! [`harden_process`](crate::harden::harden_process) is not suitable (most
//! likely too strict).
//!
//! # Examples
//! In the next example we grant the `PROCESS_CREATE_PROCESS` permissions in
//! addition to the default ones, to the process user (i.e. the user who is
//! running the program). This allows another program running as the same user
//! to attach a process as a subprocess to your process (potentially
//! dangerous...).
//!
//! ```
//! #[cfg(windows)]
//! fn harden_process() -> Result<(), secmem_proc::error::EmptySystemError> {
//!     use windows::Win32::System::Threading::{
//!         PROCESS_CREATE_PROCESS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
//!         PROCESS_TERMINATE,
//!     };
//!
//!     use secmem_proc::win_acl::{AddAllowAceAcl, EmptyAcl, TokenUser};
//!
//!     // First obtain the SID of the process user
//!     let user = TokenUser::process_user()?;
//!     let sid = user.sid();
//!
//!     // Now specify the ACL we want to create
//!     // Only things explicitly allowed with `AddAllowAceAcl` will be allowed; noting else
//!     let acl_spec = EmptyAcl;
//!     let access_mask = PROCESS_QUERY_LIMITED_INFORMATION
//!         | PROCESS_TERMINATE
//!         | PROCESS_SYNCHRONIZE
//!         | PROCESS_CREATE_PROCESS;
//!     let acl_spec = AddAllowAceAcl::new(acl_spec, access_mask, sid);
//!
//!     // Create ACL and set as process DACL
//!     let acl = acl_spec.create()?;
//!     acl.set_process_dacl_protected()
//! }
//!
//! // call `harden_process` as defined above in `main`
//! # #[cfg(windows)]
//! # harden_process();
//! ```

use crate::error::{AllocErr, SysErr};
use crate::internals::win32 as internals;

mod win {
    // import structures
    pub(super) use windows::Win32::Security::Authorization::SE_KERNEL_OBJECT;
    pub use windows::Win32::System::Threading::PROCESS_ACCESS_RIGHTS;

    // import constants
    pub(super) use windows::Win32::Security::TOKEN_QUERY;
}

pub use internals::SidRef;
pub use win::PROCESS_ACCESS_RIGHTS as ProcessAccessRights;

/// Completed (initialized) ACL.
pub struct Acl(internals::AclBox);

impl Acl {
    /// Set the ACL `self` as protected DACL for the current process.
    pub fn set_process_dacl_protected<E: SysErr>(&self) -> Result<(), E> {
        // SAFETY: `get_process_handle()` gives a valid handle to an `SE_KERNEL_OBJECT`
        // type object
        unsafe {
            self.0
                .set_protected(internals::get_process_handle(), win::SE_KERNEL_OBJECT)
        }
    }
}

/// User associated with an access token.
pub struct TokenUser(internals::TokenUserBox);

impl TokenUser {
    /// Get a reference to the user SID.
    #[must_use]
    pub fn sid<'a>(&'a self) -> SidRef<'a> {
        self.0.sid()
    }

    /// Create [`TokenUser`] for the user of the current process.
    pub fn process_user<E: SysErr + AllocErr>() -> Result<Self, E> {
        // SAFETY: `get_process_handle()` gives a valid process handle
        let process_tok = unsafe {
            internals::AccessToken::open_process_token(
                internals::get_process_handle(),
                win::TOKEN_QUERY,
            )
        }?;
        let user = process_tok.get_token_user()?;
        Ok(Self(user))
    }
}

/// Module with some complicated machinery to enable safe construction of ACLs
/// with guarantied correct allocation size without using an intermediate
/// [`Vec`] (which would require std).
mod acl_construction {
    use super::*;

    // not exported out of module (so module private)
    /// Owned ACL during initialisation (i.e. when some ACEs haven't yet been
    /// added, while space for them was allocated during creation).
    pub struct AclPartial(internals::AclBox);
    impl AclPartial {
        /// Turn into a finished ACL.
        ///
        /// This is safe since any [`AclPartial`] is initialised as an ACL and
        /// thus can safely used as such. However, calling this method when the
        /// ACL hasn't been (fully) filled with ACEs is a logic error. No ACEs
        /// can be added afterwards.
        fn declare_final(self) -> Acl {
            Acl(self.0)
        }
    }

    // not exported out of module (so module private)
    /// Helper trait for constructing an ACL with a properly sized allocation
    /// safely.
    pub trait AclConstruction {
        /// Construct an ACL according to the specification `self`, giving the
        /// caller the ability to modify the allocation size through the
        /// callback `f`.
        fn realize_with_size<E: SysErr + AllocErr, F: FnOnce(&mut internals::AclSize)>(
            self,
            f: F,
        ) -> Result<AclPartial, E>;
    }

    /// Constructor for an empty ACL.
    #[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
    pub struct EmptyAcl;

    impl EmptyAcl {
        #[must_use]
        pub fn new() -> Self {
            EmptyAcl
        }

        pub fn create<E: SysErr + AllocErr>(self) -> Result<Acl, E> {
            let acl = self.realize_with_size(|_s| {})?;
            Ok(acl.declare_final())
        }
    }

    impl AclConstruction for EmptyAcl {
        fn realize_with_size<E: SysErr + AllocErr, F: FnOnce(&mut internals::AclSize)>(
            self,
            f: F,
        ) -> Result<AclPartial, E> {
            let mut size = internals::AclSize::new();
            f(&mut size);
            let acl = size.allocate()?;
            Ok(AclPartial(acl))
        }
    }

    /// Constructor for an ACL `constructor` with an additional allowed ACE.
    pub struct AddAllowAceAcl<'a, C: AclConstruction> {
        constructor: C,
        access_mask: ProcessAccessRights,
        sid: SidRef<'a>,
    }

    impl<'a, C: AclConstruction> AddAllowAceAcl<'a, C> {
        pub fn new(constructor: C, access_mask: ProcessAccessRights, sid: SidRef<'a>) -> Self {
            AddAllowAceAcl {
                constructor,
                access_mask,
                sid,
            }
        }

        pub fn create<E: SysErr + AllocErr>(self) -> Result<Acl, E> {
            let acl = self.realize_with_size(|_s| {})?;
            Ok(acl.declare_final())
        }
    }

    impl<'a, C: AclConstruction> AclConstruction for AddAllowAceAcl<'a, C> {
        fn realize_with_size<E: SysErr + AllocErr, F: FnOnce(&mut internals::AclSize)>(
            self,
            f: F,
        ) -> Result<AclPartial, E> {
            let mut acl = self.constructor.realize_with_size(|size| {
                size.add_allowed_ace(self.sid.len());
                f(size);
            })?;
            unsafe { acl.0.add_allowed_ace(self.access_mask, self.sid) }?;
            Ok(acl)
        }
    }

    /// Constructor for an ACL `constructor` with an additional denied ACE.
    pub struct AddDenyAceAcl<'a, C: AclConstruction> {
        constructor: C,
        access_mask: ProcessAccessRights,
        sid: SidRef<'a>,
    }

    impl<'a, C: AclConstruction> AddDenyAceAcl<'a, C> {
        pub fn new(constructor: C, access_mask: ProcessAccessRights, sid: SidRef<'a>) -> Self {
            AddDenyAceAcl {
                constructor,
                access_mask,
                sid,
            }
        }

        pub fn create<E: SysErr + AllocErr>(self) -> Result<Acl, E> {
            let acl = self.realize_with_size(|_s| {})?;
            Ok(acl.declare_final())
        }
    }

    impl<'a, C: AclConstruction> AclConstruction for AddDenyAceAcl<'a, C> {
        fn realize_with_size<E: SysErr + AllocErr, F: FnOnce(&mut internals::AclSize)>(
            self,
            f: F,
        ) -> Result<AclPartial, E> {
            let mut acl = self.constructor.realize_with_size(|size| {
                size.add_denied_ace(self.sid.len());
                f(size);
            })?;
            unsafe { acl.0.add_denied_ace(self.access_mask, self.sid) }?;
            Ok(acl)
        }
    }
}

pub use acl_construction::{AddAllowAceAcl, AddDenyAceAcl, EmptyAcl};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::TestSysErr;

    #[test]
    fn create_empty_acl() {
        let acl_constructor = EmptyAcl::new();
        let acl = acl_constructor
            .create::<TestSysErr>()
            .expect("could not create ACL");
    }

    #[test]
    fn create_allow_ace_acl() {
        use windows::Win32::System::Threading::PROCESS_TERMINATE;

        let user =
            TokenUser::process_user::<TestSysErr>().expect("could not get process token user");
        let sid = user.sid();

        let acl_constructor = EmptyAcl::new();
        let acl_constructor = AddAllowAceAcl::new(acl_constructor, PROCESS_TERMINATE, sid);
        let acl = acl_constructor
            .create::<TestSysErr>()
            .expect("could not create ACL");
    }

    #[test]
    fn create_deny_ace_acl() {
        use windows::Win32::System::Threading::PROCESS_CREATE_PROCESS;

        let user =
            TokenUser::process_user::<TestSysErr>().expect("could not get process token user");
        let sid = user.sid();

        let acl_constructor = EmptyAcl::new();
        let acl_constructor = AddDenyAceAcl::new(acl_constructor, PROCESS_CREATE_PROCESS, sid);
        let acl = acl_constructor
            .create::<TestSysErr>()
            .expect("could not create ACL");
    }
}
