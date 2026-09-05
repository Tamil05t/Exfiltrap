// ExFilTrap desktop wrapper (Tauri).
//
// A thin, unprivileged native shell around the detection service's local
// web UI (http://127.0.0.1:5050). Tauri was chosen over Electron because
// it uses the OS webview (WebView2 on Windows, WebKitGTK on Linux):
// tens of MB of RAM instead of a bundled Chromium, and a small binary.
//
// Behavior:
//   * starts hidden, polls the service API until it answers, then shows
//   * lives in the system tray (show / quit)
//   * NEVER elevates and never spawns privileged processes itself — the
//     service (systemd unit / Windows Service) owns all privileged work

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::net::TcpStream;
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
        let _ = window.eval(
            "window.location.replace('http://127.0.0.1:5050');",
        );
        let _ = window.set_focus();
    }
}

fn main() {
    let show = CustomMenuItem::new("show".to_string(), "Show dashboard".to_string());
    let quit = CustomMenuItem::new("quit".to_string(), "Quit".to_string());
    let tray_menu = SystemTrayMenu::new()
        .add_item(show)
        .add_item(quit);
    let tray = SystemTray::new()
        .with_menu(tray_menu)
        .with_tooltip("ExFilTrap — DNS exfiltration monitor");

    tauri::Builder::default()
        .system_tray(tray)
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
            // The window starts on the bundled waiting page (visible from
            // the first frame) and navigates to the dashboard the moment
            // the detection service answers on the local API.
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
