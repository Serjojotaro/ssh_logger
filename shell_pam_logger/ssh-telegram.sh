#!/bin/bash

BOT_TOKEN=""
CHAT_ID=""

HOSTNAME=$(hostname)
DATE=$(date "+%Y-%m-%d %H:%M:%S")

MESSAGE="
🔐 *SSH login*
🖥 Host: \`$HOSTNAME\`
👤 User: \`$PAM_USER\`
🌍 IP: \`$PAM_RHOST\`
⏰ Time: \`$DATE\`
"

curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
  -d chat_id="${CHAT_ID}" \
  -d parse_mode="Markdown" \
  --data-urlencode text="$MESSAGE" > /dev/null
