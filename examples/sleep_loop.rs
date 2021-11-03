//! Used for testing purposes.

fn main() {
    // call `secmem_proc::harden_process` before doing anything else, to harden the
    // process against low-privileged attackers trying to obtain secret parts of
    // memory which will be handled by the process
    if secmem_proc::harden_process().is_err() {
        panic!("ERROR: could not harden process, exiting");
    }
    // rest of your program
    loop {
        let sec = std::time::Duration::from_millis(1000);
        std::thread::sleep(sec);
    }
}
