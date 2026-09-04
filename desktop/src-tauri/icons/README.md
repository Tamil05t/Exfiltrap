# Icons

Tauri requires platform icons before building. Generate them all from one
1024x1024 PNG (make one, save it as `icon-source.png` here, then):

    npm install
    npx tauri icon icon-source.png

That writes `icon.ico`, `icon.icns`, and every PNG size this folder needs.
