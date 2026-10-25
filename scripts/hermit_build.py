#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Validate the source directory used by Hermit's nested kernel build."""
import json
from pathlib import Path
import re


def verify_kernel_source(messages, kernel):
    """Reject xtask binaries whose embedded source path belongs to an old build."""
    builds = [message for message in messages
              if message.get("reason") == "build-script-executed"
              and "#hermit@" in message.get("package_id", "")]
    if len(builds) != 1:
        raise ValueError("Expected exactly one Hermit build-script record")
    log = Path(builds[0]["out_dir"]).parent / "stderr"
    directories = []
    for line in log.read_text().splitlines():
        if '"rustc" "--crate-type=staticlib"' not in line:
            continue
        match = re.match(r'^\$ cd ("(?:[^"\\]|\\.)*") && ', line)
        if not match:
            raise ValueError("Unrecognized Hermit kernel compiler command")
        directories.append(Path(json.loads(match[1])).resolve())
    if directories != [Path(kernel).resolve()]:
        raise ValueError("Hermit cached build helper used a different kernel source directory")
