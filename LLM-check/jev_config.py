"""Read TypeSafe configuration without executing .env content or logging credentials."""

import os
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_ENV_FILE = Path(__file__).resolve().parent / ".env"
NAMES = ("TYPESAFE_API_KEY", "TYPESAFE_BASE_URL", "TYPESAFE_DEFAULT_MODEL")


def read_settings(env_file=DEFAULT_ENV_FILE, require_key=False):
    values = {}
    path = Path(env_file)
    if path.exists():
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[7:].strip()
            if "=" not in line:
                raise ValueError("Invalid .env assignment on line " + str(number))
            name, value = (part.strip() for part in line.split("=", 1))
            if name not in NAMES:
                continue
            if value.startswith(("'", '"')):
                if len(value) < 2 or value[-1] != value[0]:
                    raise ValueError("Unclosed .env quote on line " + str(number))
                value = value[1:-1]
            values[name] = value
    for name in NAMES:
        if os.getenv(name, "").strip():
            values[name] = os.environ[name].strip()
    key = values.get("TYPESAFE_API_KEY", "").strip()
    if key and (not key.isascii() or any(char.isspace() or ord(char) < 32 for char in key)):
        raise ValueError("TYPESAFE_API_KEY must contain an ASCII token without whitespace")
    if require_key and not key:
        raise ValueError("Fill TYPESAFE_API_KEY in " + str(path) + " or the environment")
    base_url = values.get("TYPESAFE_BASE_URL", "").strip().rstrip("/") or "https://api.typesafe.ai"
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("TYPESAFE_BASE_URL must be an HTTPS API root without embedded credentials")
    return {"api_key": key, "base_url": base_url,
            "model": values.get("TYPESAFE_DEFAULT_MODEL", "").strip() or "jev-latest"}


def public_settings(settings):
    return {"api_key_configured": bool(settings["api_key"]), "base_url": settings["base_url"], "model": settings["model"]}
