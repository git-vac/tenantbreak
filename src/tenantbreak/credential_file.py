"""Private credential snapshots, separate from shareable run evidence."""

from contextlib import contextmanager
import json
import os
from pathlib import Path

from .auth import ENV
from .config import PolicyError, decode_json, _object


def private_path(path):
    path = Path(path)
    root = Path.cwd().resolve() / "private"
    if root.is_symlink() or path.is_symlink() or not path.resolve().is_relative_to(root):
        raise PolicyError("credential files must stay inside the current directory's private/ folder")
    return path


def read_credentials(path):
    path = private_path(path)
    try:
        with path.open("rb") as stream:
            data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise PolicyError("credential file exceeds 1 MiB")
        document = decode_json(data)
        _object(document, {"format", "environment"}, {"format", "environment"}, "credential file")
        if document["format"] != "tenantbreak-credentials-v1" or not isinstance(document["environment"], dict):
            raise PolicyError("unsupported credential file")
        for name, value in document["environment"].items():
            if not ENV.fullmatch(name) or not isinstance(value, str) or not 1 <= len(value) <= 8192:
                raise PolicyError("invalid credential file entries")
        return document["environment"]
    except (ValueError, OSError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, PolicyError):
            raise
        raise PolicyError("cannot read private credential file") from exc


@contextmanager
def refresh_output(path):
    path = private_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w+", encoding="utf-8", newline="\n") as stream:
        state = {"format": "tenantbreak-credentials-v1", "environment": {}}
        def save(identity, updates):
            state["environment"].update(updates)
            content = json.dumps(state, ensure_ascii=True, indent=2) + "\n"
            stream.seek(0)
            stream.write(content)
            stream.truncate()
            stream.flush()
            os.fsync(stream.fileno())
        save(None, {})
        yield save
