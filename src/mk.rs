use std::ffi::CString;
use std::io::Error;
use std::path::PathBuf;

#[cfg(unix)]
pub fn mkfifo(path: &std::ffi::CStr, mode: libc::mode_t) -> Result<(), Error> {
    let ret = unsafe { libc::mkfifo(path.as_ptr(), mode) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub fn mknod(path: &std::ffi::CStr, mode: libc::mode_t, dev: libc::dev_t) -> Result<(), Error> {
    let ret = unsafe { libc::mknod(path.as_ptr(), mode, dev) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub fn set_file_modified_time(
    path: &std::ffi::CStr,
    t: std::time::SystemTime,
) -> Result<(), Error> {
    use libc::AT_FDCWD;
    use libc::AT_SYMLINK_NOFOLLOW;
    use libc::UTIME_OMIT;
    let Ok(d) = t.duration_since(std::time::SystemTime::UNIX_EPOCH) else {
        return Ok(());
    };
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: d.as_secs() as libc::time_t,
            tv_nsec: d.subsec_nanos() as libc::c_long,
        },
    ];
    let ret =
        unsafe { libc::utimensat(AT_FDCWD, path.as_ptr(), times.as_ptr(), AT_SYMLINK_NOFOLLOW) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
pub fn lchown(path: &std::ffi::CStr, uid: libc::uid_t, gid: libc::gid_t) -> Result<(), Error> {
    let ret = unsafe { libc::lchown(path.as_ptr(), uid, gid) };
    if ret < 0 {
        return Err(Error::last_os_error());
    }
    Ok(())
}

pub fn path_to_c_string(path: PathBuf) -> Result<CString, Error> {
    Ok(CString::new(path.into_os_string().into_encoded_bytes())?)
}
