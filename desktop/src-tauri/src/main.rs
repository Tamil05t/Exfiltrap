// ExFilTrap desktop shell (Tauri v2) — ALL-IN-ONE product.
//
// The detection engine (PyInstaller `exfiltrap` service binary) ships
// INSIDE this package as a bundled resource. On launch the app AUTO-STARTS
// the engine when nothing is already serving the API (one root
// authorization via pkexec), then navigates to the dashboard as soon as the
// API answers. A manual Start button on the waiting screen remains as a
// fallback when auto-start is declined or polkit is unavailable.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::path::BaseDirectory;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent, TrayIconBuilder};
use tauri::Manager;

const API_HOST: &str = "127.0.0.1";
const API_PORT: u16 = 5050;

fn api_up() -> bool {
    TcpStream::connect((API_HOST, API_PORT)).is_ok()
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.set_focus();
    }
}

fn navigate_to_dashboard(app: &tauri::AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.eval("window.location.replace('http://127.0.0.1:5050');");
        let _ = w.set_focus();
    }
}

/// Locate the bundled engine across resource layouts and dev trees.
fn service_binary(app: &tauri::AppHandle) -> Option<PathBuf> {
    if let Ok(over) = std::env::var("EXFILTRAP_SERVICE_BIN") {
        let p = PathBuf::from(over);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        // Tauri's real AppImage/deb resource layout (mainBinaryName dir):
        //   ${APPDIR}/usr/lib/ex-fil-trap/resources/exfiltrap-engine
        "resources/exfiltrap-engine/exfiltrap",
        "exfiltrap-engine/exfiltrap",
        "exfiltrap-engine",
        "exfiltrap/exfiltrap",
        "dist/exfiltrap/exfiltrap",
    ] {
        if let Ok(p) = app
            .path()
            .resolve(candidate, BaseDirectory::Resource)
        {
            if p.exists() {
                return Some(p);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let p = parent.join(candidate);
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Resource directory that contains the bundled engine.
fn engine_resource_dir(app: &tauri::AppHandle) -> Option<PathBuf> {
    for candidate in ["resources/exfiltrap-engine", "exfiltrap-engine"] {
        if let Ok(p) = app.path().resolve(candidate, BaseDirectory::Resource) {
            if p.join("exfiltrap").exists() {
                return Some(p);
            }
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                let p = parent.join(candidate);
                if p.join("exfiltrap").exists() {
                    return Some(p);
                }
            }
        }
    }
    None
}

/// Recursive directory copy (std only) — used to stage the engine off an
/// AppImage FUSE mount into a location root can read.
fn copy_dir_recursive(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        let to = dst.join(entry.file_name());
        if ty.is_dir() {
            copy_dir_recursive(&entry.path(), &to)?;
        } else {
            std::fs::copy(entry.path(), &to)?;
        }
    }
    Ok(())
}

/// Start the bundled detection engine as root via pkexec (polkit prompt).
/// The engine is COPIED to /var/lib/exfiltrap/engine and launched from
/// there: deb/AppImage installs carry resource files without the execute
/// bit, and AppImage mounts are read-only — running from a root-owned copy
/// fixes both. Any previously running engine is stopped first, so pressing
/// Start always yields a fresh, working session.
/// Inside a Flatpak, this process is sandboxed but the engine must run on
/// the HOST (root, CAP_NET_RAW, host firewall). The sandbox is escaped
/// deliberately via `flatpak-spawn --host pkexec`; the root-side script
/// then sees HOST paths, so the engine source dir is rewritten from the
/// in-sandbox /app prefix to the app's files as visible from the host.
fn host_visible_engine_dir(res_dir: &str) -> String {
    match std::env::var("FLATPAK_ID") {
        Ok(id) => match res_dir.strip_prefix("/app") {
            Some(rest) => format!("/var/lib/flatpak/app/{id}/current/active/files{rest}"),
            None => res_dir.to_string(),
        },
        Err(_) => res_dir.to_string(),
    }
}

fn in_flatpak() -> bool {
    std::env::var("FLATPAK_ID").is_ok()
}

/// Build the root-side launch script for a given interface hint. Shared by
/// the interactive Start button and the launch-time auto-start so both use
/// identical, tested logic.
fn build_launch_script(app: &tauri::AppHandle, iface: &str) -> Result<String, String> {
    let res_dir = service_binary(app)
        .and_then(|bin| bin.parent().map(|p| p.to_path_buf()))
        .or_else(|| engine_resource_dir(app))
        .ok_or_else(|| "bundled detection engine not found in this package".to_string())?;
    let mut res_dir = host_visible_engine_dir(&res_dir.to_string_lossy());
    // AppImage gotcha, found live: FUSE mounts serve ONLY the user who
    // launched them — root gets EPERM ("Permission denied" on cp), so a
    // root-side copy straight from /tmp/.mount_* fails silently. When the
    // engine lives on an AppImage mount, stage a user-readable mirror in
    // /tmp first; root copies from there.
    if res_dir.contains("/.mount_") || res_dir.starts_with("/tmp/.mount_") {
        let stage = std::env::temp_dir().join("exfiltrap-engine-stage");
        let _ = std::fs::remove_dir_all(&stage);
        copy_dir_recursive(Path::new(&res_dir), &stage)
            .map_err(|e| format!("staging AppImage engine failed: {e}"))?;
        res_dir = stage.to_string_lossy().to_string();
    }
    // Whitelist interface characters — this string is embedded into a
    // root-side shell script, so anything outside [A-Za-z0-9._-] is hostile.
    let iface: String = iface
        .trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    let iface_arg = if iface.is_empty() {
        String::new()
    } else {
        format!("--iface '{iface}'")
    };
    // Root-side script: stop any old engine, copy the engine to a
    // writable+executable location, then launch it detached. `nohup … >>`
    // appends so the log keeps the full history of the session.
    //
    // `pkill -x` (exact process-name match) is load-bearing: `pkill -f`
    // matches full command lines, and this script's own command line
    // contains "exfiltrap" (engine paths), so `-f` SIGTERM'd pkexec AND
    // this sh the instant it ran — auth succeeded, engine never launched,
    // and the app surfaced the signal death as "pkexec exit code -1".
    // Neither pkexec, sh, nor this app binary (ex-fil-trap) is named
    // "exfiltrap", so `-x` hits only the engine itself.
    //
    // `set -e` on the copy chain: a failed cp previously fell through to
    // "success" (the AppImage/root-EPERM case) and the UI waited on an
    // engine that never came. Errors now surface through pkexec's stderr.
    Ok(format!(
        "set -e; \
         systemctl stop 'exfiltrap@*' >/dev/null 2>&1 || true; \
         pkill -x exfiltrap >/dev/null 2>&1 || true; sleep 1; \
         mkdir -p /var/lib/exfiltrap; \
         rm -rf /var/lib/exfiltrap/engine; \
         cp -r '{res_dir}' /var/lib/exfiltrap/engine; \
         chmod -R +x /var/lib/exfiltrap/engine; \
         nohup '/var/lib/exfiltrap/engine/exfiltrap' service {iface_arg} \
         >> /tmp/exfiltrap-service.log 2>&1 & \
         i=0; while [ $i -lt 20 ]; do \
           pgrep -x exfiltrap >/dev/null 2>&1 && exit 0; \
           i=$((i+1)); sleep 0.5; \
         done; \
         echo 'engine process did not come up after launch — see /tmp/exfiltrap-service.log'; exit 1"
    ))
}

/// Run a root-side script through pkexec (blocking worker). Inside a
/// Flatpak the sandbox cannot talk to the host polkit directly; the
/// sanctioned escape is flatpak-spawn --host (needs the
/// org.freedesktop.Flatpak talk permission, set in the manifest).
async fn run_pkexec(script: String) -> Result<(), String> {
    let flatpak = in_flatpak();
    let out = tauri::async_runtime::spawn_blocking(move || {
        let mut cmd = if flatpak {
            let mut c = Command::new("flatpak-spawn");
            c.arg("--host").arg("pkexec");
            c
        } else {
            Command::new("pkexec")
        };
        cmd.arg("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .map_err(|e| format!("pkexec failed: {e}"))
    })
    .await
    .map_err(|e| format!("join error: {e}"))??;
    if out.status.success() {
        Ok(())
    } else {
        // The script reports its own failures (copy errors, launch check)
        // on stdout; pkexec/policy errors arrive on stderr.
        let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let code = out.status.code().unwrap_or(-1);
        let detail = if !stdout.is_empty() {
            stdout
        } else if !stderr.is_empty() {
            stderr
        } else {
            match code {
                // No exit code = killed by a signal: the root script died
                // before finishing (pre-1.3.1 this was its own `pkill -f`
                // self-match; any recurrence means something killed pkexec).
                -1 => "start script was killed by a signal — engine did not launch".to_string(),
                _ => format!("exit status {code}"),
            }
        };
        Err(format!("pkexec failed: {detail}"))
    }
}

#[tauri::command]
async fn start_service(
    app: tauri::AppHandle,
    iface: String,
) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        return Err("On Windows, run as Administrator: exfiltrap.exe service --iface <adapter>\n(or install ExFilTrap-Setup.exe — the service starts automatically)".to_string());
    }
    let script = build_launch_script(&app, &iface)?;
    run_pkexec(script).await?;
    Ok("service start requested".into())
}

/// Launch-time auto-start: when the API is not already up and a bundled
/// engine is present, start it WITHOUT waiting for the user to click. This
/// is what turns the AppImage from a static splash into a self-starting
/// product. Failures are non-fatal — the waiting screen still offers the
/// manual Start button and surfaces the engine log.
async fn autostart_engine(app: tauri::AppHandle) {
    if api_up() {
        return;
    }
    let script = match build_launch_script(&app, "") {
        Ok(s) => s,
        // No bundled engine (e.g. a dashboard-only run): nothing to do.
        Err(_) => return,
    };
    match run_pkexec(script).await {
        Ok(()) => {}
        Err(e) => {
            // Polkit may be unavailable in a headless session; the manual
            // button remains, so just log for the splash's log viewer.
            eprintln!("[exfiltrap] auto-start did not complete: {e}");
        }
    }
}

/// Tail of a log string (used by service_log).
fn tail_string(log: &str, max_bytes: usize) -> String {
    let len = log.len();
    if len > max_bytes {
        // Walk forward to a UTF-8 char boundary (no nightly APIs).
        let mut start = len - max_bytes;
        while start < len && !log.is_char_boundary(start) {
            start += 1;
        }
        log[start..].to_string()
    } else {
        log.to_string()
    }
}

/// Tail of the engine log, for surfacing startup failures in the waiting
/// screen (waiting.html polls this after a failed/timeout start).
#[tauri::command]
fn service_log() -> String {
    const LOG: &str = "/tmp/exfiltrap-service.log";
    // The engine runs on the HOST, and a Flatpak's /tmp is private — read
    // the host log through the same sanctioned sandbox escape.
    let log = if in_flatpak() {
        Command::new("flatpak-spawn")
            .args(["--host", "cat", LOG])
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    } else {
        std::fs::read_to_string(LOG).unwrap_or_default()
    };
    // Tail only — the log grows unbounded across sessions and the
    // whole file would stall the webview.
    tail_string(&log, 8000)
}

fn main() {
    // WebKitGTK on Linux: the DMABUF renderer and the accelerated
    // compositor are responsible for blank white windows and frozen,
    // unclickable UIs on many GPU/driver combinations (NVIDIA, some Intel
    // and virtual machines). Both switches are the established fix; they
    // only affect this process and cost nothing on healthy systems.
    std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    std::env::set_var("WEBKIT_DISABLE_COMPOSITING_MODE", "1");
    // WebKit's bubblewrap sandbox cannot set up its mounts inside an
    // AppImage (namespace restrictions) and renders an EMPTY window — the
    // known fix is running without it. The app only displays a localhost
    // dashboard, so the webview sandbox adds no security here anyway.
    std::env::set_var("WEBKIT_FORCE_SANDBOX", "0");
    // webkit 2.46+ renamed it (the old var above prints a deprecation
    // warning on new webkits and no longer disables anything there):
    std::env::set_var("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", "1");

    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start_service, service_log])
        .setup(|app| {
            // Window + tray icon: set explicitly at runtime, otherwise the
            // taskbar shows a blank placeholder when the app is not an
            // installed desktop entry (e.g. running the AppImage).
            let icon = tauri::image::Image::from_bytes(include_bytes!(
                "../icons/icon.png"
            ))
            .map_err(|e| e.to_string())?
            .to_owned();
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_icon(icon.clone());
            }

            // System tray (v2: built in code, icon from the bundle defaults).
            let show =
                MenuItem::with_id(app, "show", "Show dashboard", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(icon)
                .tooltip("ExFilTrap — DNS exfiltration monitor")
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "show" => show_main_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        show_main_window(tray.app_handle());
                    }
                })
                .build(app)?;

            // Poll for the service; navigate to the dashboard when it's up.
            //
            // If nothing is serving the API yet, actively start the bundled
            // engine instead of leaving the user on a static splash — this
            // is the fix for "the AppImage just sits there". A short grace
            // period first lets an already-running service win without us
            // stopping/restarting it. Auto-start is best-effort: if polkit
            // is unavailable the splash's manual Start button still works.
            let handle = app.handle().clone();
            let autostart_handle = app.handle().clone();
            thread::spawn(move || {
                if cfg!(not(target_os = "windows")) {
                    tauri::async_runtime::spawn(autostart_engine(autostart_handle));
                }
                loop {
                    if api_up() {
                        navigate_to_dashboard(&handle);
                        break;
                    }
                    thread::sleep(Duration::from_secs(2));
                }
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running ExFilTrap desktop");
}
