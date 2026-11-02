"""`python -m api hash-password`: print an APP_USERS entry without storing the password."""

import getpass
import json
import sys

from api.auth import hasher


def main() -> int:
    if sys.argv[1:] != ["hash-password"]:
        print("usage: python -m api hash-password", file=sys.stderr)
        return 2
    username = input("username: ")
    password = getpass.getpass("password: ")
    if password != getpass.getpass("again: "):
        print("passwords differ", file=sys.stderr)
        return 1
    entry = json.dumps({username: hasher.hash(password)})
    print("APP_USERS entry (merge several users into one JSON object):")
    print(entry)
    print("Single-quote it, in .env and for `fly secrets set`, so the shell leaves `$` alone:")
    print(f"APP_USERS='{entry}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
