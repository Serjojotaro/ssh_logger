#!/bin/bash
# Уведомление о SSH-логине в Telegram через pam_exec.
# Секреты не хранятся в этом файле: BOT_TOKEN и CHAT_ID читаются из
# /etc/ssh-telegram.conf (chmod 600, владелец root).

# Реагируем только на открытие сессии (иначе дубли на su/cron и т.п.)
[ "$PAM_TYPE" = "open_session" ] || exit 0

CONFIG_FILE="${SSH_TELEGRAM_CONFIG:-/etc/ssh-telegram.conf}"
[ -r "$CONFIG_FILE" ] && . "$CONFIG_FILE"

if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
    logger -t ssh-telegram "missing BOT_TOKEN/CHAT_ID in $CONFIG_FILE"
    exit 0
fi

MESSAGE="SSH login
Host: $(hostname)
User: $PAM_USER
IP:   $PAM_RHOST
Time: $(date "+%Y-%m-%d %H:%M:%S")"

# parse_mode не используется: спецсимволы в имени/IP иначе ломают разметку.
# --max-time обязателен: без него недоступный Telegram подвешивает логин.
if ! curl -sf --max-time 10 -o /dev/null \
    "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    --data-urlencode chat_id="${CHAT_ID}" \
    --data-urlencode text="$MESSAGE"; then
    logger -t ssh-telegram "failed to send notification"
fi

# Ошибка доставки не должна влиять на аутентификацию
exit 0
