use once_cell::sync::Lazy;
use predicates::prelude::PredicateBooleanExt;

static TEST_PROGRAM: Lazy<escargot::CargoRun> = Lazy::new(build_test_program);

fn build_test_program() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .example("test_program")
        .run()
        .expect("failed to build test program")
}

/// Run the program untraced and check that it succeeds, printing "SECRET".
#[test]
fn test_untraced() {
    let test_prog = &*TEST_PROGRAM;
    let mut cmd = assert_cmd::Command::from_std(test_prog.command());
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("SECRET"));
}

/// Run the program under strace and check that it fails, without printing
/// "SECRET".
#[cfg(target_os = "linux")]
#[test]
fn test_strace() {
    let test_prog = &*TEST_PROGRAM;
    let mut cmd = assert_cmd::Command::new("strace");
    cmd.arg(test_prog.path());
    cmd.assert()
        .failure()
        .stdout(predicates::str::contains("SECRET").not());
}
