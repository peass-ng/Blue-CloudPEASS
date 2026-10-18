"""Initialize named volumes, then permanently drop root before running service."""
import os
from pathlib import Path
import sys


def main():
    os.umask(0o077)
    if os.getuid() == 0:
        if os.getenv("PEASO_INITIALIZE") == "1":
            for setting in ("PEASO_STATE_DIR", "PEASO_IDENTITY_DIR"):
                path = Path(os.environ[setting])
                path.mkdir(parents=True, exist_ok=True, mode=0o700)
                os.chown(path, 10001, 10001)
                os.chmod(path, 0o700)
        os.setgroups([])
        os.setgid(10001)
        os.setuid(10001)
    os.execvp(sys.argv[1], sys.argv[1:])


if __name__ == "__main__":
    main()
