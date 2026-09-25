"""Copy a fixture program and its local runtime into a disposable chroot."""

from __future__ import annotations

from pathlib import Path
import re
import shlex
import shutil
import subprocess


def copy_program(root: Path, source: Path, destination: str) -> None:
    target = root / destination.lstrip("/")
    if target.exists():
        return
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    with source.open("rb") as executable:
        header = executable.read(256)
    if header.startswith(b"#!"):
        interpreter = shlex.split(header.split(b"\n", 1)[0][2:].decode())[0]
        if not interpreter.startswith("/"):
            raise RuntimeError(f"non-absolute fixture interpreter: {source}")
        copy_program(root, Path(interpreter), interpreter)
        return
    linked = subprocess.run(
        ["ldd", str(source)], capture_output=True, text=True, timeout=10, check=False,
    )
    dependencies = linked.stdout + linked.stderr
    static = any(message in dependencies for message in ("not a dynamic executable", "statically linked"))
    if linked.returncode and not static:
        raise RuntimeError(f"cannot inspect fixture libraries: {source}: {dependencies}")
    if "=> not found" in dependencies:
        raise RuntimeError(f"missing fixture library: {source}: {dependencies}")
    for name in re.findall(r"(?:=>\s+|^\s*)(/[^\s]+)", dependencies, re.MULTILINE):
        library = root / name.lstrip("/")
        library.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(name, library)
