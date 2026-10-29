#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""A cached xtask must not silently select an old kernel source tree."""
import copy
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


class HermitNetworkSourceTests(unittest.TestCase):
    def test_only_the_reviewed_networking_patch_sources_are_accepted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            revision = 'a' * 40
            (root / 'Cargo.toml').write_text(
                '[patch.crates-io]\n'
                'socket2 = { path = "vendor/socket2" }\n'
                'hyper-util = { path = "vendor/hyper-util" }\n'
                f'tokio = {{ git = "https://example.com/tokio", rev = "{revision}" }}\n')
            packages = [
                {'id':name, 'name':name, 'source':None,
                 'manifest_path':str(root / 'vendor' / name / 'Cargo.toml')}
                for name in ('socket2', 'hyper-util')]
            packages.append({'id':'tokio', 'name':'tokio',
                'source':f'git+https://example.com/tokio?rev={revision}#{revision}'})
            metadata = {'packages':packages, 'resolve':{'nodes':[{'id':p['id']} for p in packages]}}
            build.verify_network_sources(metadata, root)
            # Metadata may inventory a crate that is not part of the selected target graph.
            inactive = {**metadata, 'packages':[*packages, {'id':'unused', 'name':'rustls-platform-verifier'}]}
            build.verify_network_sources(inactive, root)
            for name in ('tokio', 'socket2', 'hyper-util'):
                for mutation in ('registry', 'missing', 'duplicate'):
                    changed = copy.deepcopy(metadata)
                    package = next(p for p in changed['packages'] if p['name'] == name)
                    if mutation == 'registry':
                        package['source'] = 'registry+https://github.com/rust-lang/crates.io-index'
                    elif mutation == 'missing':
                        changed['resolve']['nodes'] = [n for n in changed['resolve']['nodes'] if n['id'] != name]
                    else:
                        changed['packages'].append({**package, 'id':'duplicate'})
                        changed['resolve']['nodes'].append({'id':'duplicate'})
                    with self.subTest(name=name, mutation=mutation), self.assertRaisesRegex(ValueError, name):
                        build.verify_network_sources(changed, root)
            changed = copy.deepcopy(metadata)
            changed['packages'][0]['manifest_path'] = '/unreviewed/socket2/Cargo.toml'
            with self.assertRaisesRegex(ValueError, 'socket2'):
                build.verify_network_sources(changed, root)
            changed = copy.deepcopy(metadata)
            changed['packages'][-1]['source'] = f'git+https://example.com/tokio?rev={revision}#' + 'b'*40
            with self.assertRaisesRegex(ValueError, 'tokio'):
                build.verify_network_sources(changed, root)
            unsupported = {'id':'platform', 'name':'rustls-platform-verifier'}
            changed = copy.deepcopy(metadata)
            changed['packages'].append(unsupported)
            changed['resolve']['nodes'].append({'id':'platform'})
            with self.assertRaisesRegex(ValueError, 'platform-verifier'):
                build.verify_network_sources(changed, root)


if __name__ == "__main__":
    unittest.main()
