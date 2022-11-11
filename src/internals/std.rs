/// Error that the `TracerPid` was not found in `/proc/self/status`.
#[derive(Debug, Clone, thiserror::Error)]
#[error("`TracerPid` entry not found in `/proc/self/status`")]
pub struct TracerPidNotFound;

/// Check whether the current process is being traced by reading
/// `/proc/self/status`. Returns the tracer pid or `0` if not traced.
#[cfg(target_os = "linux")]
fn get_tracer_pid() -> anyhow::Result<usize> {
    // TODO: check that `/proc` is indeed procfs, e.g. use rustix's
    // `proc_self_status` currently, however, this seems to error when
    // `/proc/self` is root owned

    // let fd = rustix::io::proc_self_status()?;
    // let file = std::fs::File::from(fd);
    let file = std::fs::File::open("/proc/self/status")?;
    let status = std::io::read_to_string(file)?;
    for line in status.lines() {
        if let Some(tracer_pid_str) = line.strip_prefix("TracerPid:") {
            return Ok(tracer_pid_str.trim().parse()?);
        }
    }
    Err(anyhow::Error::new(TracerPidNotFound))
}

/// Check whether the current process is being traced by reading
/// `/proc/self/status`.
#[cfg(target_os = "linux")]
pub fn is_tracer_present() -> anyhow::Result<Option<rustix::process::RawNonZeroPid>> {
    let tracer_pid = get_tracer_pid()?;
    let pid = rustix::process::RawPid::try_from(tracer_pid)?;
    Ok(rustix::process::RawNonZeroPid::new(pid))
}
