#!/bin/bash
mkdir -p docs/images

echo "🐳 Starting the Lab..."
docker compose -f lab/docker-compose.yml up -d
sleep 3

echo "🖱️  Please click on this terminal window to tell the script where to capture..."
TERM_WIN_ID=$(xdotool selectwindow)
echo "✅ Terminal window targeted (ID: $TERM_WIN_ID)"

echo "📸 Capturing 01: CLI Banner..."
clear
archangel -h
sleep 1
maim -i "$TERM_WIN_ID" docs/images/01-banner-help.png
echo "✅ Saved 01-banner-help.png"

echo "🎥 Recording 02: Recon Progress (as a GIF-ready cast)..."
asciinema rec -c "archangel scan http://127.0.0.1:8088/index.php --no-interact" docs/images/02-recon-progress.cast
echo "✅ Saved 02-recon-progress.cast (convert to GIF later)"

echo "📸 Capturing 03: Oracle Confirmed..."
clear
archangel scan http://127.0.0.1:8088/index.php --no-interact --auto-confirm
sleep 2
maim -i "$TERM_WIN_ID" docs/images/03-oracle-confirmed.png
echo "✅ Saved 03-oracle-confirmed.png"

echo ""
echo "⚠️  ACTION REQUIRED: For 04-markdown-report.png"
echo "The report should have automatically opened in your GUI editor."
echo "Take a manual screenshot of the editor and save it as:"
echo "docs/images/04-markdown-report.png"
echo ""
echo "🎉 Screenshot capture complete!"
