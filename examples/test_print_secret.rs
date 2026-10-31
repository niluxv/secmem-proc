//! Used for testing purposes.

fn main() -> Result<(), secmem_proc::error::Error> {
    match secmem_proc::harden_process() {
        Ok(_) => {
            println!("SECRET");
            Ok(())
        },
        Err(e) => Err(e),
    }
}
