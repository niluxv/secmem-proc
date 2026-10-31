//! Used for testing purposes.

use std::{arch::asm, env::args, io::stdin};

fn main() {
    let mut args = args();
    assert!(args.next().is_some(), "no zero-th commandline argument");
    let harden = if let Some(arg) = args.next() {
        assert_eq!(arg, "--harden");
        true
    } else {
        false
    };

    if harden {
        if let Err(e) = secmem_proc::harden_process() {
            panic!(
                "ERROR: fatal error during process hardening, exiting: {}",
                e
            );
        };
        println!("hardened");
    } else {
        println!("not hardened");
    }

    let secret: u32 = 37;
    let ptr: *const u32 = &secret;

    // Story: `ptr` is sent to the parent process
    unsafe {
        asm!("/* {} */", in(reg) ptr);
    }
    println!("{:?}", ptr);

    let mut buf = String::new();
    stdin().read_line(&mut buf).unwrap();

    // make sure `secret` is still around
    let ptr: *const u32 = &secret;
    unsafe {
        asm!("/* {} */", in(reg) ptr);
    }
}
