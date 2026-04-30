"""
Управление пользователями Крипта
─────────────────────────────────
Запуск:
    python create_user.py              — добавить / изменить пользователя
    python create_user.py --list       — список пользователей
    python create_user.py --delete username — удалить пользователя
"""

import sys
import json
import bcrypt
import getpass
from pathlib import Path

USERS_FILE = Path("users.json")


def load():
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text())


def save(users):
    USERS_FILE.write_text(json.dumps(users, indent=2, ensure_ascii=False))


def list_users():
    users = load()
    if not users:
        print("Пользователей нет.")
        return
    print(f"\n{'Логин':<20} {'Роль':<12} {'Хэш (bcrypt)'}")
    print("─" * 70)
    for u, data in users.items():
        role = data.get("role", "user")
        h = data.get("hashed_password", "")
        print(f"{u:<20} {role:<12} {h[:35]}…")
    print()


def create_or_update():
    username = input("Логин: ").strip()
    if not username:
        print("Логин не может быть пустым.")
        return

    while True:
        password = getpass.getpass("Пароль (не отображается): ")
        confirm  = getpass.getpass("Повторите пароль: ")
        if password == confirm:
            break
        print("Пароли не совпадают, попробуйте ещё раз.")

    if len(password) < 6:
        print("Пароль слишком короткий (минимум 6 символов).")
        return

    role = input("Роль (admin/user) [user]: ").strip() or "user"
    if role not in ("admin", "user"):
        print("Роль должна быть 'admin' или 'user'.")
        return

    users = load()
    action = "обновлён" if username in users else "создан"
    users[username] = {
        "username": username,
        "hashed_password": bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode(),
        "role": role,
    }
    save(users)
    print(f"\n✓ Пользователь «{username}» {action} (роль: {role}).")


def delete_user(username):
    users = load()
    if username not in users:
        print(f"Пользователь «{username}» не найден.")
        return
    confirm = input(f"Удалить «{username}»? (y/N): ").strip().lower()
    if confirm == 'y':
        del users[username]
        save(users)
        print(f"✓ Пользователь «{username}» удалён.")
    else:
        print("Отменено.")


if __name__ == "__main__":
    args = sys.argv[1:]
    if "--list" in args:
        list_users()
    elif "--delete" in args:
        idx = args.index("--delete")
        if idx + 1 < len(args):
            delete_user(args[idx + 1])
        else:
            print("Укажите логин: python create_user.py --delete <логин>")
    else:
        create_or_update()
