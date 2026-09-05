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

/// Start the bundled detection engine as root via pkexec (polkit prompt).
/// The service keeps running independently of the desktop app.
#[tauri::command]
fn start_service(app: tauri::AppHandle, iface: String) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        return Err("On Windows, run as Administrator: exfiltrap.exe service --iface <adapter>\n(or install ExFilTrap-Setup.exe — the service starts automatically)".to_string());
    }
    let bin = service_binary(&app).ok_or_else(|| {
        "bundled detection engine not found in this package".to_string()
    })?;
    let bin = bin.to_string_lossy().to_string();
    let iface = iface.replace(['\'', ';', '\\'], "");
    let script = format!(
        "nohup '{bin}' service --iface '{iface}' >/tmp/exfiltrap-service.log 2>&1 &"
    );
    let out = Command::new("pkexec")
        .arg("sh")
        .arg("-c")
        .arg(&script)
        .output()
        .map_err(|e| format!("pkexec failed: {e}"))?;
    if out.status.success() {
        Ok("service start requested".into())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![start_service])
        .setup(|app| {
            // System tray (v2: built in code, icon from the bundle defaults).
            let show =
                MenuItem::with_id(app, "show", "Show dashboard", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show, &quit])?;
            let _tray = TrayIconBuilder::with_id("main")
                .icon(app.default_window_icon().expect("bundle icon").clone())
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
