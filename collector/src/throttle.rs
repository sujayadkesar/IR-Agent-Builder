//! Runtime resource governance driven by the build config: silent-mode console
//! suppression and a CPU usage cap. Both are best-effort — a failure here must
//! never abort the collection, only log.

/// When `silent`, detach from the console so no window is shown on the endpoint.
///
/// We use `FreeConsole` rather than hiding the window (`ShowWindow(SW_HIDE)`):
/// hiding acts on whatever console the process is *attached to*, which when the
/// collector is launched from an existing terminal is the operator's shared
/// console — hiding that would make the operator's window vanish. `FreeConsole`
/// only detaches this process; a parent terminal is untouched, and a console the
/// process owns (double-click / GPO launch) closes cleanly.
pub fn hide_console_if_silent(silent: bool) {
    if !silent {
        return;
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let _ = windows::Win32::System::Console::FreeConsole();
    }
}

/// Apply a CPU usage cap. `pct` is the configured percentage; `0` (or `>=100`)
/// means unthrottled. On Windows we set a *real* hard cap via a Job Object CPU
/// rate control; if that can't be applied we fall back to lowering the process
/// priority class. On Linux we lower scheduling priority (`nice`).
pub fn apply_cpu_limit(pct: u8) {
    if pct == 0 || pct >= 100 {
        log::info!("[cpu] no CPU limit (cpu_limit_percent={pct})");
        return;
    }

    #[cfg(target_os = "windows")]
    {
        if apply_job_object_cap(pct) {
            log::info!("[cpu] hard CPU cap set to {pct}% (Job Object rate control)");
        } else if apply_priority_fallback(pct) {
            log::info!("[cpu] Job Object cap unavailable; lowered process priority instead (target ~{pct}%)");
        } else {
            log::warn!("[cpu] could not apply any CPU limit (requested {pct}%)");
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        // nice 0..=19 — higher = less CPU. Map low pct -> high nice.
        let nice = (((100 - pct as i32) * 19) / 100).clamp(0, 19);
        let rc = unsafe { libc::setpriority(libc::PRIO_PROCESS, 0, nice) };
        if rc == 0 {
            log::info!("[cpu] lowered scheduling priority to nice={nice} (target ~{pct}%)");
        } else {
            log::warn!("[cpu] setpriority(nice={nice}) failed (requested {pct}%)");
        }
    }
}

#[cfg(target_os = "windows")]
fn apply_job_object_cap(pct: u8) -> bool {
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, SetInformationJobObject,
        JobObjectCpuRateControlInformation, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
        JOB_OBJECT_CPU_RATE_CONTROL_ENABLE, JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let job = match CreateJobObjectW(None, windows::core::PCWSTR::null()) {
            Ok(h) if !h.is_invalid() => h,
            _ => return false,
        };
        let mut info: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION = std::mem::zeroed();
        info.ControlFlags =
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP;
        // CpuRate is in 1/100 of a percent: pct% -> pct * 100.
        info.Anonymous.CpuRate = (pct as u32) * 100;

        let set_ok = SetInformationJobObject(
            job,
            JobObjectCpuRateControlInformation,
            &info as *const _ as *const core::ffi::c_void,
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )
        .is_ok();
        let assign_ok = AssignProcessToJobObject(job, GetCurrentProcess()).is_ok();

        if set_ok && assign_ok {
            // Intentionally do NOT close `job`: the handle (and thus the rate cap)
            // must outlive this function for the whole process lifetime. HANDLE has
            // no Drop, so letting it go out of scope leaks it, which is what we want.
            true
        } else {
            let _ = windows::Win32::Foundation::CloseHandle(job);
            false
        }
    }
}

#[cfg(target_os = "windows")]
fn apply_priority_fallback(pct: u8) -> bool {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, BELOW_NORMAL_PRIORITY_CLASS, IDLE_PRIORITY_CLASS,
    };
    let class = if pct <= 33 {
        IDLE_PRIORITY_CLASS
    } else {
        BELOW_NORMAL_PRIORITY_CLASS
    };
    unsafe { SetPriorityClass(GetCurrentProcess(), class).is_ok() }
}
