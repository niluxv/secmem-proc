#[cfg(target_os = "linux")]
use predicates::prelude::PredicateBooleanExt;
use std::sync::LazyLock;

static TEST_PROGRAM: LazyLock<escargot::CargoRun> = LazyLock::new(build_test_program);

fn build_test_program() -> escargot::CargoRun {
    escargot::CargoBuild::new()
        .example("test_print_secret")
        .run()
        .expect("failed to build test program")
}

/// Run the program untraced and check that it succeeds, printing "SECRET".
#[test]
fn test_untraced() {
    let mut cmd: assert_cmd::Command = (*TEST_PROGRAM).command().into();
    cmd.assert()
        .success()
        .stdout(predicates::str::contains("SECRET"));
}

/// Run the program under strace and check that it fails, without printing
/// "SECRET".
#[cfg(target_os = "linux")]
#[test]
fn test_strace() {
    let mut cmd = assert_cmd::Command::new("strace");
    cmd.arg((*TEST_PROGRAM).path());
    cmd.assert()
        .failure()
        .stdout(predicates::str::contains("SECRET").not());
}
