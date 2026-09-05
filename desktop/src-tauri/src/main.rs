// ExFilTrap desktop wrapper (Tauri).
//
// ALL-IN-ONE product: this app BUNDLES the detection engine
// (the `exfiltrap` service binary ships inside the package as a resource)
// and can start it locally with a single root authorization (polkit/pkexec
// on Linux). No Python, no source, no separate downloads.
//
// Flow: window opens on the bundled waiting screen -> "Start service"
// invokes start_service() which runs the bundled engine via pkexec ->
// the window auto-navigates to the dashboard when the API answers.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
use std::process::Command;
use std::thread;
use std::time::Duration;

use tauri::{CustomMenuItem, Manager, SystemTray, SystemTrayEvent, SystemTrayMenu};

const API_HOST: &str = "127.0.0.1";
const API_PORT: u16 = 5050;

fn api_up() -> bool {
    TcpStream::connect((API_HOST, API_PORT)).is_ok()
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// Navigate the shell window to the service dashboard once it is up.
fn navigate_to_dashboard(app: &tauri::AppHandle) {
    if let Some(window) = app.get_window("main") {
        let _ = window.eval("window.location.replace('http://127.0.0.1:5050');");
        let _ = window.set_focus();
    }
}

/// Locate the bundled service binary across packaging layouts
/// (AppImage mount, deb resource dir, dev tree).
fn service_binary(app: &tauri::AppHandle) -> Option<std::path::PathBuf> {
    if let Ok(over) = std::env::var("EXFILTRAP_SERVICE_BIN") {
        let p = std::path::PathBuf::from(over);
        if p.exists() {
            return Some(p);
        }
    }
    for candidate in [
        "exfiltrap/exfiltrap",
        "exfiltrap",
        "bin/exfiltrap",
        "dist/exfiltrap/exfiltrap",
        "dist/exfiltrap",
    ] {
        if let Some(p) = app.path_resolver().resolve_resource(candidate) {
            if p.exists() {
                return Some(p);
            }
        }
    }
    None
}

/// Start the bundled detection service as root via pkexec (polkit shows the
/// authorization dialog). The service keeps running independently of the app.
#[tauri::command]
fn start_service(app: tauri::AppHandle, iface: String) -> Result<String, String> {
    if cfg!(target_os = "windows") {
        return Err("On Windows, run as Administrator: exfiltrap.exe service --iface <adapter>\n(or install ExFilTrap-Setup.exe — the service starts automatically)".to_string());
    }
    let bin = service_binary(&app)
        .ok_or_else(|| "bundled service binary not found in this package".to_string())?;
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
    let show = CustomMenuItem::new("show".to_string(), "Show dashboard".to_string());
    let quit = CustomMenuItem::new("quit".to_string(), "Quit".to_string());
    let tray_menu = SystemTrayMenu::new().add_item(show).add_item(quit);
    let tray = SystemTray::new()
        .with_menu(tray_menu)
        .with_tooltip("ExFilTrap — DNS exfiltration monitor");

    tauri::Builder::default()
        .system_tray(tray)
        .invoke_handler(tauri::generate_handler![start_service])
        .on_system_tray_event(|app, event| match event {
            SystemTrayEvent::MenuItemClick { id, .. } => match id.as_str() {
                "show" => show_main_window(app),
                "quit" => app.exit(0),
                _ => {}
            },
            SystemTrayEvent::LeftClick { .. } => show_main_window(app),
            _ => {}
        })
        .setup(|app| {
            // Window is visible from the first frame on the bundled waiting
            // page; navigate to the dashboard the moment the API answers.
            let handle = app.app_handle();
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
