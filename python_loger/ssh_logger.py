#!/usr/bin/env python3
import json
import os
import re
import sys
import time
import datetime
import requests

# ---------- SETTINGS ----------
# Значения из окружения имеют приоритет, чтобы токен не хранился в коде.
# Unit-файл подключает EnvironmentFile=/etc/ssh_notifier.env (chmod 600).
TOKEN = os.environ.get("TELEGRAM_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")

LOGFILE = os.environ.get("SSHD_LOG", "/var/log/auth.log")  # CentOS/RedHat: "/var/log/secure"
STATE_FILE = os.environ.get("STATE_FILE", "/var/lib/ssh_notifier/sessions.json")

# Минимальный интервал между уведомлениями об ошибках входа с одной пары (user, ip)
FAIL_COOLDOWN = 60
MAX_TRACKED = 5000  # защита от роста памяти при распределённой атаке


def ts():
    return datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")


def log_err(msg):
    print(f"[{ts()}] {msg}", file=sys.stderr)


# ---------- TELEGRAM ----------
def send(msg):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    params = {"chat_id": CHAT_ID, "text": msg}
    for attempt in range(3):
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code == 429:
                retry_after = r.json().get("parameters", {}).get("retry_after", 2)
                time.sleep(float(retry_after))
                continue
            r.raise_for_status()
            return True
        except Exception as e:
            log_err(f"Telegram send error: {e}")
            time.sleep(2 * (attempt + 1))
    return False


# ---------- STATE ----------
# Активные сессии {pid: user}, переживают рестарт демона
sessions = {}
# IP источника по pid из "Connection from" (sshd пишет его с тем же pid)
conn_ips = {}
# (user, ip) -> [last_sent_ts, suppressed_count]
fail_state = {}


def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as e:
        log_err(f"Cannot read state file: {e}")
        return {}


def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(sessions, f)
        os.replace(tmp, STATE_FILE)
    except OSError as e:
        log_err(f"Cannot save state file: {e}")


# ---------- LOG TAIL (rotation-aware) ----------
def open_log(seek_end=False):
    while True:
        try:
            f = open(LOGFILE, "r")
            # при старте читаем только новые строки; после ротации — с начала
            if seek_end:
                f.seek(0, 2)
            return f
        except OSError as e:
            log_err(f"Cannot open {LOGFILE}: {e}; retrying in 5s")
            time.sleep(5)


def rotated(f):
    # logrotate: create-режим меняет inode, copytruncate обнуляет размер
    try:
        st = os.stat(LOGFILE)
    except OSError:
        return False
    try:
        cur = os.fstat(f.fileno())
    except OSError:
        return True
    return st.st_ino != cur.st_ino or st.st_size < f.tell()


def follow():
    f = open_log(seek_end=True)
    while True:
        line = f.readline()
        if line:
            yield line
            continue
        if rotated(f):
            log_err(f"{LOGFILE} rotated, reopening")
            f.close()
            f = open_log()
            continue
        time.sleep(0.5)


# ---------- PARSER ----------
# На современных дистрибутивах pam_unix пишет "for user sergei(uid=1000)",
# на старых — "for user sergei"; обе формы корректны.
RE_CONN = re.compile(r"sshd\[(\d+)\]: Connection from (\S+)")
RE_OPENED = re.compile(
    r"sshd\[(\d+)\]: pam_unix\(sshd:session\): session opened for user ([^\s(]+)(?:\(uid=(\d+)\))?"
)
RE_CLOSED = re.compile(
    r"sshd\[(\d+)\]: pam_unix\(sshd:session\): session closed for user ([^\s(]+)"
)
RE_FAILED = re.compile(r"sshd\[\d+\]: Failed password for (?:invalid user )?(\S+) from (\S+)")


def notify_failed(user, ip):
    key = f"{user}@{ip}"
    stamp = time.time()
    state = fail_state.get(key)
    if state and stamp - state[0] < FAIL_COOLDOWN:
        state[1] += 1
        return
    msg = f"🚨 SSH FAILED LOGIN\nUser: {user}\nFrom: {ip}\n{ts()}"
    if state and state[1]:
        msg += f"\n(+{state[1]} аналогичных подавлено)"
    fail_state[key] = [stamp, 0]
    for k in [k for k, v in fail_state.items() if stamp - v[0] > FAIL_COOLDOWN]:
        del fail_state[k]
    send(msg)


def main():
    sessions.update(load_state())
    for line in follow():
        if m := RE_CONN.search(line):
            conn_ips[m.group(1)] = m.group(2)
            if len(conn_ips) > MAX_TRACKED:
                conn_ips.clear()
            continue

        if m := RE_FAILED.search(line):
            notify_failed(m.group(1), m.group(2))
            continue

        if m := RE_OPENED.search(line):
            pid, user, uid = m.groups()
            sessions[pid] = user
            save_state()
            uid_line = f"\nUID: {uid}" if uid else ""
            send(
                f"✅ SSH LOGIN\nUser: {user}{uid_line}\nFrom: {conn_ips.get(pid, 'unknown')}\n"
                f"PID: {pid}\n{ts()}"
            )
            continue

        if m := RE_CLOSED.search(line):
            pid, user = m.groups()
            # шлём logout только по сессии, которую сами видели открытой
            if pid in sessions:
                del sessions[pid]
                conn_ips.pop(pid, None)
                save_state()
                send(f"👋 SSH LOGOUT\nUser: {user}\nPID: {pid}\n{ts()}")
            continue


if __name__ == "__main__":
    main()
