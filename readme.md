# SSH_LOGGER

*SSH-logger* — утилита-демон для отслеживания SSH-подключений на Linux-хосте
с отправкой уведомлений через Telegram-бота.

Два варианта:

- `python_loger/` — демон, читающий лог sshd (`/var/log/auth.log`);
- `shell_pam_logger/` — скрипт, вызываемый напрямую из PAM (`pam_exec`).

Python-вариант использует библиотеки: `requests` и стандартные модули.

------

# Как установить (Python-вариант)

1. Создать файл конфигурации с секретами:

   ```
   /etc/ssh_notifier.env   (chmod 600)
   ```

   содержимое:

   ```
   TELEGRAM_TOKEN=123456:ABC...
   TELEGRAM_CHAT_ID=-1001234567890
   # опционально:
   #SSHD_LOG=/var/log/secure          # путь к логу (по умолчанию /var/log/auth.log)
   #STATE_FILE=/var/lib/ssh_notifier/sessions.json
   ```

2. Скопировать `ssh_logger.py` в `/usr/bin/ssh_logger.py` (или изменить путь в unit-файле).
3. Скопировать `ssh_notifier.service` в `/etc/systemd/system/`.
4. Запустить и добавить в автозагрузку:

   ```
   sudo systemctl start ssh_notifier
   sudo systemctl enable ssh_notifier
   ```

Демон присылает LOGIN (пользователь, UID, IP источника, PID сессии),
LOGOUT и сообщения о неудачных попытках аутентификации.

Поведение:

- состояние активных сессий сохраняется в `STATE_FILE` — после рестарта
  демона logout-и не теряются;
- ротация лога (`logrotate`) обрабатывается автоматически;
- сообщения об ошибках входа от одной пары (user, IP) не чаще одного
  раза в минуту — брутфорс не превращается в спам;
- ошибки отправки в Telegram пишутся в stderr (видно в `journalctl -u ssh_notifier`).

**Важно:** на системах без `/var/log/auth.log` (RHEL8+ и свежие Ubuntu/Debian
с minimal-образом, где всё ведётся в journald) установите `rsyslog` или
измените `SSHD_LOG` на доступный файл лога. Чтение напрямую из journald этим демоном не поддерживается.

# Как установить (PAM-вариант)

1. Создать `/etc/ssh-telegram.conf` (chmod 600):

   ```
   BOT_TOKEN=123456:ABC...
   CHAT_ID=-1001234567890
   ```

2. Скопировать `ssh-telegram.sh` в `/usr/local/sbin/ssh-telegram.sh`, `chmod 700`.
3. В `/etc/pam.d/sshd` добавить строку:

   ```
   session  optional  pam_exec.so  /usr/local/sbin/ssh-telegram.sh
   ```

`optional` — ошибка уведомления не должна блокировать вход. Скрипт
срабатывает только на `open_session`, запрос к Telegram ограничен
`--max-time 10`, чтобы недоступная сеть не подвешивала логин.

# Ограничения

- Уведомления о логинах/ошибках — это алёртинг, а не аудит команд.
  Для аудита используйте `auditd`; для защиты SSH — `fail2ban`, Wazuh или SIEM.
- На сетевом оборудовании (коммутаторы, шлюзы) проект неприменим:
  используйте syslog-форвардинг на лог-сервер.
