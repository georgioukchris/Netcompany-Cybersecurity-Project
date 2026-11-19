"""NexGuard account management (run inside the backend container).

  docker compose exec backend python manage_users.py list
  docker compose exec backend python manage_users.py create maria@company.gr --name "Μαρία Π." --role admin
  docker compose exec backend python manage_users.py set-password maria@company.gr
  docker compose exec backend python manage_users.py disable maria@company.gr
  docker compose exec backend python manage_users.py enable maria@company.gr

Passwords are asked interactively (never on the command line, so they stay out of shell history).
"""
import argparse
import getpass
import sys

import auth
from database import get_connection, init_db


def ask_password() -> str:
    while True:
        pw = getpass.getpass("Κωδικός: ")
        if (problem := auth.password_problem(pw)):
            print(problem)
            continue
        if getpass.getpass("Επιβεβαίωση: ") != pw:
            print("Οι κωδικοί δεν ταιριάζουν.")
            continue
        return pw


def main() -> int:
    parser = argparse.ArgumentParser(description="NexGuard accounts")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("create")
    c.add_argument("email")
    c.add_argument("--name", default="")
    c.add_argument("--role", choices=["user", "admin"], default="user")
    c.add_argument("--google-only", action="store_true", help="χωρίς κωδικό· σύνδεση μόνο με Google")
    for name in ("set-password", "disable", "enable"):
        sub.add_parser(name).add_argument("email")
    args = parser.parse_args()
    init_db()

    if args.cmd == "list":
        with get_connection() as conn:
            rows = conn.execute("""SELECT email, display_name, role, disabled, password_hash IS NOT NULL AS pw,
                                          google_sub IS NOT NULL AS google, last_login_at FROM app_users ORDER BY email""").fetchall()
        for r in rows:
            methods = "+".join(m for m, on in (("κωδικός", r["pw"]), ("Google", r["google"])) if on) or "—"
            print(f"{r['email']:<36} {r['role']:<6} {'ΑΠΕΝΕΡΓΟΣ' if r['disabled'] else 'ενεργός':<10} {methods:<16} {r['display_name']}")
        return 0
    if args.cmd == "create":
        if auth.get_user_by_email(args.email):
            print("Υπάρχει ήδη λογαριασμός με αυτό το email.")
            return 1
        user = auth.create_user(args.email, args.name, args.role, None if args.google_only else ask_password())
        print(f"Δημιουργήθηκε: {user['email']} ({user['role']})")
        return 0
    user = auth.get_user_by_email(args.email)
    if not user:
        print("Δεν βρέθηκε λογαριασμός.")
        return 1
    if args.cmd == "set-password":
        auth.set_password(user["id"], ask_password())
        auth.delete_user_sessions(user["id"])
        print("Ο κωδικός άλλαξε· όλες οι συνδέσεις του χρήστη έκλεισαν.")
    else:
        with get_connection() as conn:
            conn.execute("UPDATE app_users SET disabled = %s WHERE id = %s", (args.cmd == "disable", user["id"]))
        if args.cmd == "disable":
            auth.delete_user_sessions(user["id"])
        print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
