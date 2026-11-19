#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build/image/Блокнот.app/Contents/MacOS
app=build/image/Блокнот.app
mkdir -p "$app/Contents/Resources"
cp kraken-mark.png Kraken.icns "$app/Contents/Resources/"
cp Info.plist "$app/Contents/Info.plist"
swiftc -target "$(uname -m)-apple-macos13.0" -parse-as-library -O Notepad.swift -o "$app/Contents/MacOS/Notepad"
codesign --force --sign - "$app"
ln -sfn /Applications build/image/Applications
hdiutil create -ov -volname Блокнот -srcfolder build/image -format UDZO Блокнот.dmg
