// Detect whether the current process is running as elevated administrator (or LocalSystem).

#[cfg(windows)]
pub fn is_elevated() -> bool {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        );
        let _ = windows::Win32::Foundation::CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    // For dev builds on non-Windows hosts.
    unsafe { libc_geteuid() == 0 }
}

#[cfg(not(windows))]
extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
