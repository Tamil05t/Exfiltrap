// ExFilTrap desktop shell (Tauri v2) — ALL-IN-ONE product.
//
// The detection engine (PyInstaller `exfiltrap` service binary) ships
// INSIDE this package as a bundled resource. The waiting screen starts it
// with one root authorization (pkexec) and the window auto-navigates to
// the dashboard when the API answers.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::path::PathBuf;
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
        "exfiltrap-engine/exfiltrap",
        "resources/exfiltrap-engine/exfiltrap",
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
    for candidate in ["exfiltrap-engine", "resources/exfiltrap-engine"] {
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

/// Start the bundled detection engine as root via pkexec (polkit prompt).
/// The engine is COPIED to /var/lib/exfiltrap/engine and launched from
/// there: deb/AppImage installs carry resource files without the execute
/// bit, and AppImage mounts are read-only — running from a root-owned copy
/// fixes both. Any previously running engine is stopped first, so pressing
/// Start always yields a fresh, working session.
#[tauri::command]
async fn start_service(
    app: tauri::AppHandle,
    iface: String,
) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        return Err("On Windows, run as Administrator: exfiltrap.exe service --iface <adapter>\n(or install ExFilTrap-Setup.exe — the service starts automatically)".to_string());
    }
    let res_dir = service_binary(&app)
        .and_then(|bin| bin.parent().map(|p| p.to_path_buf()))
        .or_else(|| engine_resource_dir(&app))
        .ok_or_else(|| "bundled detection engine not found in this package".to_string())?;
    let res_dir = res_dir.to_string_lossy().to_string();
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
    let script = format!(
        "systemctl stop 'exfiltrap@*' >/dev/null 2>&1; \
         pkill -x exfiltrap >/dev/null 2>&1; sleep 1; \
         mkdir -p /var/lib/exfiltrap; \
         rm -rf /var/lib/exfiltrap/engine; \
         cp -r '{res_dir}' /var/lib/exfiltrap/engine; \
         chmod -R +x /var/lib/exfiltrap/engine; \
         nohup '/var/lib/exfiltrap/engine/exfiltrap' service {iface_arg} \
         >> /tmp/exfiltrap-service.log 2>&1 &"
    );
    // pkexec blocks until the polkit dialog is answered — run it on a
    // blocking worker so the webview UI never freezes.
    let out = tauri::async_runtime::spawn_blocking(move || {
        Command::new("pkexec")
            .arg("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .map_err(|e| format!("pkexec failed: {e}"))
    })
    .await
    .map_err(|e| format!("join error: {e}"))??;
    if out.status.success() {
        Ok("service start requested".into())
    } else {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let code = out.status.code().unwrap_or(-1);
        let detail = if stderr.is_empty() {
            match code {
                // No exit code = killed by a signal: the root script died
                // before finishing (pre-1.3.1 this was its own `pkill -f`
                // self-match; any recurrence means something killed pkexec).
                -1 => "start script was killed by a signal — engine did not launch".to_string(),
                _ => format!("exit status {code}"),
            }
        } else {
            stderr
        };
        Err(format!("pkexec failed: {detail}"))
    }
}

/// Tail of the engine log, for surfacing startup failures in the waiting
/// screen (waiting.html polls this after a failed/timeout start).
#[tauri::command]
fn service_log() -> String {
    match std::fs::read_to_string("/tmp/exfiltrap-service.log") {
        Ok(log) => {
            // Tail only — the log grows unbounded across sessions and the
            // whole file would stall the webview.
            let len = log.len();
            if len > 8000 {
                // Walk forward to a UTF-8 char boundary (no nightly APIs).
                let mut start = len - 8000;
                while start < len && !log.is_char_boundary(start) {
                    start += 1;
                }
                log[start..].to_string()
            } else {
                log
            }
        }
        Err(_) => String::new(),
    }
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
            let handle = app.handle().clone();
            thread::spawn(move || loop {
                if api_up() {
                    navigate_to_dashboard(&handle);
                    break;
                }
                thread::sleep(Duration::from_secs(2));
            });
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running ExFilTrap desktop");
}
