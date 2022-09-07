//! Safer Windows DACL API.

use crate::error::{AllocErr, SysErr};
use crate::internals::win32 as internals;
use winapi::shared::minwindef::DWORD as Dword;

pub use internals::SidRef;

/// Completed (initialized) ACL.
pub struct Acl(internals::AclBox);

impl Acl {
    /// Set the ACL `self` as protected DACL for the current process.
    pub fn set_process_dacl_protected<E: SysErr>(&self) -> Result<(), E> {
        use winapi::um::accctrl::SE_KERNEL_OBJECT;

        // SAFETY: `get_process_handle()` gives a valid handle to an `SE_KERNEL_OBJECT`
        // type object
        unsafe {
            self.0
                .set_protected(internals::get_process_handle(), SE_KERNEL_OBJECT)
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
        use winapi::um::winnt::TOKEN_QUERY;
        // SAFETY: `get_process_handle()` gives a valid process handle
        let process_tok = unsafe {
            internals::AccessToken::open_process_token(internals::get_process_handle(), TOKEN_QUERY)
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
        access_mask: Dword,
        sid: SidRef<'a>,
    }

    impl<'a, C: AclConstruction> AddAllowAceAcl<'a, C> {
        pub fn new(constructor: C, access_mask: Dword, sid: SidRef<'a>) -> Self {
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
}

pub use acl_construction::{AddAllowAceAcl, EmptyAcl};

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
        use winapi::um::winnt::PROCESS_TERMINATE;

        let user =
            TokenUser::process_user::<TestSysErr>().expect("could not get process token user");
        let sid = user.sid();

        let acl_constructor = EmptyAcl::new();
        let acl_constructor = AddAllowAceAcl::new(acl_constructor, PROCESS_TERMINATE, sid);
        let acl = acl_constructor
            .create::<TestSysErr>()
            .expect("could not create ACL");
    }
}
