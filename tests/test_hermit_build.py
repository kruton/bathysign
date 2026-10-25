#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""A cached xtask must not silently select an old kernel source tree."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location("hermit_build", Path(__file__).resolve().parents[1] / "scripts/hermit_build.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class KernelSourceTests(unittest.TestCase):
    def test_checks_inner_compilation_instead_of_requested_wrapper_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out = root / "hermit-build/out"
            out.mkdir(parents=True)
            requested, stale = root / "patched kernel", root / "old-kernel"
            messages = [{"reason": "build-script-executed", "package_id": "git+https://example/hermit-rs#hermit@0.13.0", "out_dir": str(out)}]
            wrapper = f'$ cd {json.dumps(str(requested))} && "cargo" "run" "--package=xtask"\n'
            for actual, valid in ((requested, True), (stale, False)):
                (out.parent / "stderr").write_text(wrapper + f'$ cd {json.dumps(str(actual))} && "cargo" "rustc" "--crate-type=staticlib"\n')
                if valid:
                    build.verify_kernel_source(messages, requested)
                else:
                    with self.assertRaisesRegex(ValueError, "different kernel source"):
                        build.verify_kernel_source(messages, requested)
            (out.parent / "stderr").write_text(wrapper)
            with self.assertRaises(ValueError):
                build.verify_kernel_source(messages, requested)
            for ambiguous in ([], messages * 2):
                with self.assertRaises(ValueError):
                    build.verify_kernel_source(ambiguous, requested)


if __name__ == "__main__":
    unittest.main()
