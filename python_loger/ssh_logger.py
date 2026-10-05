#!/usr/bin/env python3
import time
import datetime
import requests
import re

# ---------- SETTINGS ----------
TOKEN = "" # токен вашего бота
CHAT_ID = "" # айди вашего чата, в который отправлять сообщения 

# ---------- TELEGRAM ----------
def send(msg):
    params = {"chat_id": CHAT_ID, "text": msg}
    try:
        requests.get(f"https://api.telegram.org/bot{TOKEN}/sendMessage", params=params, timeout=5)
    except Exception as e:
        print("Error sending to Telegram:", e)

# ---------- PARSER ----------
LOGFILE = "/var/log/auth.log"   # на CentOS/RedHat: "/var/log/secure"

# Регулярки для событий с PID
RE_OPENED = re.compile(r"sshd\[(\d+)\]: pam_unix\(sshd:session\): session opened for user (\S+)")
RE_CLOSED = re.compile(r"sshd\[(\d+)\]: pam_unix\(sshd:session\): session closed for user (\S+)")
RE_FAILED = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

# Словарь активных сессий: {pid: user}
sessions = {}

def follow(file):
    file.seek(0, 2)  # в конец
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def main():
    with open(LOGFILE, "r") as f:
        for line in follow(f):
            ts = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")

            # Неудачные попытки
            if m := RE_FAILED.search(line):
                user, ip = m.groups()
                send(f"🚨 SSH FAILED LOGIN\nUser: {user}\nFrom: {ip}\n{ts}")
                continue

            # Логин (session opened)
            if m := RE_OPENED.search(line):
                pid, user = m.groups()
                sessions[pid] = user
                send(f"✅ SSH LOGIN\nUser: {user}\ FROM: {ip}\nPID: {pid}\n{ts}")
                continue

            # Логаут (session closed)
            if m := RE_CLOSED.search(line):
                pid, user = m.groups()
                user = user.strip()
                if pid in sessions:
                 # if user != "root": # небольшой КОСТЫЛЬ, иначе бот начнёт спамить сообшения об логауте рута. Разкомментить, если начинается спам логаут сообщениями!
                    send(f"👋 SSH LOGOUT\nUser: {user}\nPID: {pid}\n{ts}")
                    del sessions[pid]
                continue

if __name__ == "__main__":
    main()




