#!/usr/bin/env python3
# Copyright 2026 Kenny Root
"""Verify Hermit transactions and prepare SLSA provenance. No application code executes."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.request
import zipfile

SLSA = "https://slsa.dev/provenance/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
BUILD_TYPE = "https://actions.github.io/buildtypes/workflow/v1"
MAX_BYTES = 128 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def load(data):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=unique)


def run(*args):
    return subprocess.run([str(a) for a in args], check=True, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, timeout=300).stdout


def api(path):
    return load(run("gh", "api", "--hostname", "github.com", "--method", "GET", path))


def rows(path, field=None):
    result = []
    for page in range(1, 101):
        value = api(f"{path}?per_page=100&page={page}")
        batch = value[field] if field else value
        require(isinstance(batch, list), "invalid API list")
        result.extend(batch)
        if len(batch) < 100:
            return result
    raise ValueError("pagination limit exceeded")


def valid_hash(value, size=64):
    return isinstance(value, str) and re.fullmatch(f"[a-f0-9]{{{size}}}", value) is not None


def allowed_ref(patterns, value):
    return any(value == p or (p.startswith("refs/tags/") and p.endswith("*")
               and "*" not in p[:-1] and value.startswith(p[:-1])) for p in patterns)


def verify_workflow_identity(builder):
    validate_workflow_identity(builder)
    require(len(builder["refs"]) == 1 and builder["refs"][0].startswith("refs/heads/"), "one trusted builder branch required")
    meta = api(f"repos/{builder['repository']}")
    require(meta["id"] == builder["repository_id"] and meta["visibility"] == "public", "trusted workflow repository differs")
    branch = builder["refs"][0][len("refs/heads/"):]
    require(re.fullmatch(r"[A-Za-z0-9_.\-/]+", branch) and all(part not in ("", ".", "..") for part in branch.split("/")), "unsafe builder branch")
    require(api(f"repos/{builder['repository']}/branches/{branch}")["protected"] is True, "trusted workflow branch is unprotected")


def validate_workflow_identity(builder):
    require(set(builder) == {"repository", "repository_id", "workflow", "refs"}, "unsupported workflow policy fields")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", builder["repository"]), "invalid trusted repository")
    require(type(builder["repository_id"]) is int and builder["repository_id"] > 0, "invalid trusted repository ID")
    require(re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", builder["workflow"]), "invalid trusted workflow")
    require(isinstance(builder["refs"], list) and len(builder["refs"]) == 1, "one trusted branch required")
    branch = builder["refs"][0].removeprefix("refs/heads/")
    require(builder["refs"][0].startswith("refs/heads/") and re.fullmatch(r"[A-Za-z0-9_.\-/]+", branch)
        and all(part not in ("", ".", "..") for part in branch.split("/")), "invalid trusted branch")


def verify_finalizer_certificate(policy, certificate):
    finalizer = policy["finalizer"]
    verify_workflow_identity(finalizer)
    expected = f"https://github.com/{finalizer['repository']}/{finalizer['workflow']}@{finalizer['refs'][0]}"
    require(certificate["buildSignerURI"] == expected and valid_hash(certificate["buildSignerDigest"], 40), "final attestation builder differs")
    return expected, certificate["buildSignerDigest"]


def validate_policy(policy):
    require(policy.get("receipt_namespace") == "bathysign", "unsupported receipt namespace")
    require(policy.get("version") in (3, 4) and policy.get("visibility") == "public", "version 3 public release policy required")
    require(all(k in policy for k in ("builder", "finalizer", "callers")), "required policy identities missing")
    require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", policy["repository"]), "invalid repository")
    require(isinstance(policy["repository_id"], int) and policy["repository_id"] > 0, "invalid repository ID")
    require(valid_hash(policy["policy_hash"]) and valid_hash(policy["signer_revision"], 40), "deployment policy/revision not provisioned")
    require(policy["revision"] > 0 and policy["profiles"] and policy["receipt_keys"], "incomplete signing policy")
    require(isinstance(policy["callers"], list) and policy["callers"]
        and len(set(policy["callers"])) == len(policy["callers"])
        and all(re.fullmatch(r"\.github/workflows/[A-Za-z0-9_-]+\.ya?ml", path) for path in policy["callers"]), "invalid caller allowlist")
    builder, finalizer = policy["builder"], policy["finalizer"]
    for workflow in (builder, finalizer):
        validate_workflow_identity(workflow)
        require(workflow["repository"] != policy["repository"] and workflow["repository_id"] != policy["repository_id"], "trusted workflows must be separate from source")
    require(all(finalizer[k] == builder[k] for k in ("repository", "repository_id", "refs"))
        and finalizer["workflow"] != builder["workflow"], "finalizer must be separate in the same trusted repository and branch")
    for name, profile in policy["profiles"].items():
        require(re.fullmatch(r"[a-z0-9-]{1,32}", name), "invalid profile")
        require(all(valid_hash(v) for v in profile["keys"].values() if isinstance(v, str)), "invalid key pin")
        require(all(k in profile["keys"] for k in ("original", "classical", "upload", "transparency")), "missing Android key roles")
        require(valid_hash(profile["lineage_sha256"]), "lineage is not pinned")
        require(profile["rotation_min_sdk"] in (28, 33), "unsupported rotation SDK")
    for fingerprint, certificate in policy["receipt_keys"].items():
        require(valid_hash(fingerprint) and digest(base64.b64decode(certificate, validate=True)) == fingerprint, "receipt certificate pin differs")


def verify_receipt(envelope, policy):
    value = load(envelope)
    require(set(value) == {"payloadType", "payload", "signatures"}, "unexpected envelope fields")
    require(value["payloadType"] == PAYLOAD_TYPE and len(value["signatures"]) == 1, "unsupported receipt envelope")
    sig = value["signatures"][0]
    certificate = base64.b64decode(policy["receipt_keys"][sig["keyid"]], validate=True)
    require(digest(certificate) == sig["keyid"], "receipt certificate differs")
    payload = base64.b64decode(value["payload"], validate=True)
    pae = f"DSSEv1 {len(PAYLOAD_TYPE)} {PAYLOAD_TYPE} {len(payload)} ".encode() + payload
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "cert.der").write_bytes(certificate)
        (root / "sig").write_bytes(base64.b64decode(sig["sig"], validate=True))
        (root / "pae").write_bytes(pae)
        (root / "pub.pem").write_bytes(run("openssl", "x509", "-inform", "DER", "-in", root / "cert.der", "-pubkey", "-noout"))
        run("openssl", "dgst", "-sha256", "-verify", root / "pub.pem", "-signature", root / "sig", root / "pae")
    statement = load(payload)
    require(statement["_type"] == "https://in-toto.io/Statement/v1" and statement["predicateType"] == ("urn:" + policy.get("receipt_namespace") + (":receipt:v3" if policy["version"] == 4 else ":receipt:v2")), "unsupported receipt statement")
    receipt = statement["predicate"]
    require(receipt.get("receipt_namespace") == policy.get("receipt_namespace"), "receipt namespace differs from policy")
    require(receipt["version"] == (3 if policy["version"] == 4 else 2), "unsupported receipt version")
    require(statement["subject"] == [{"name": o["name"], "digest": {"sha256": o["sha256"]}} for o in receipt["outputs"]], "receipt subject differs")
    return receipt


def verify_trust_evidence(receipt, files, policy):
    if policy["version"] == 4:
        import importlib.util
        spec = importlib.util.spec_from_file_location("signer_trust_evidence", Path(__file__).with_name("trust_evidence.py"))
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        require("trust-evidence.json" in files, "trust evidence missing")
        binding = verifier.verify(files["trust-evidence.json"], receipt, policy["trust_authority"])
        require(all(receipt["provenance"][kind]["trust_root_sha256"] == binding["target_sha256"] for kind in ("apk", "aab")), "provenance trust root differs from authenticated evidence")
    else:
        require(receipt.get("trust") is None, "static-trust receipt cannot claim dynamic trust")


def validate_transaction(receipt, policy, source_run, profile):
    job = receipt["job"]
    expected_id = f"v2-{policy['repository_id']}-{source_run['id']}-{source_run['run_attempt']}-{profile}-{policy['policy_hash']}"
    require(job == {"version": 2, "profile": profile, "id": expected_id,
        "repository_id": policy["repository_id"], "run_id": source_run["id"],
        "attempt": source_run["run_attempt"], "commit": source_run["head_sha"],
        "policy_hash": policy["policy_hash"], "revision": policy["revision"]}, "signing transaction differs")
    profile_policy = policy["profiles"][profile]
    require(receipt["repository"] == policy["repository"] and receipt["package"] == profile_policy["package"], "package/repository differs")
    require(receipt["keys"] == profile_policy["keys"], "signing key roles differ")
    require(receipt["lineage"]["sha256"] == profile_policy["lineage_sha256"] and receipt["rotation_min_sdk"] == profile_policy["rotation_min_sdk"], "rotation policy differs")
    require(receipt["hybrid_min_sdk"] == profile_policy.get("hybrid_min_sdk"), "hybrid policy differs")
    require(receipt["signer"]["revision"] == policy["signer_revision"], "signer implementation differs")
    return expected_id


def verify_provenance(path, bundle, policy, source_run, summary):
    require(digest(bundle.read_bytes()) == summary["bundle_sha256"], "upstream bundle differs")
    builder = policy["builder"]
    verified = load(run("gh", "attestation", "verify", path, "--bundle", bundle,
        "--repo", policy["repository"],
        "--signer-workflow", f"{builder['repository']}/{builder['workflow']}",
        "--signer-digest", summary["builder_commit"], "--source-digest", source_run["head_sha"],
        "--source-ref", summary["ref"], "--deny-self-hosted-runners", "--format", "json"))
    require(len(verified) == 1, "ambiguous verified provenance")
    result = verified[0]["verificationResult"]
    cert = result["signature"]["certificate"]
    statement = result["statement"]
    predicate = statement["predicate"]
    definition = predicate["buildDefinition"]
    workflow = definition["externalParameters"]["workflow"]
    uri = f"https://github.com/{policy['repository']}"
    invocation = f"{uri}/actions/runs/{source_run['id']}/attempts/{source_run['run_attempt']}"
    require(workflow["path"] in policy["callers"] and workflow["repository"] == uri and allowed_ref(policy["refs"], workflow["ref"]), "caller differs")
    expected = {"issuer": "https://token.actions.githubusercontent.com", "sourceRepositoryURI": uri,
        "sourceRepositoryIdentifier": str(policy["repository_id"]), "sourceRepositoryDigest": source_run["head_sha"],
        "sourceRepositoryRef": workflow["ref"], "buildConfigURI": f"{uri}/{workflow['path']}@{workflow['ref']}",
        "buildConfigDigest": source_run["head_sha"], "buildSignerURI": summary["builder"],
        "buildSignerDigest": summary["builder_commit"], "runInvocationURI": invocation,
        "runnerEnvironment": "github-hosted", "buildTrigger": source_run["event"],
        "sourceRepositoryVisibilityAtSigning": policy["visibility"]}
    require(all(cert.get(k) == v for k, v in expected.items()), "verified certificate claims differ")
    require(cert["subjectAlternativeName"] == summary["builder"] and result["verifiedTimestamps"], "missing verified identity/time")
    prefix = f"https://github.com/{builder['repository']}/{builder['workflow']}@"
    require(summary["builder"].startswith(prefix) and allowed_ref(builder["refs"], summary["builder"][len(prefix):]), "builder ref differs")
    require(definition["buildType"] == "https://actions.github.io/buildtypes/workflow/v1" and set(definition["externalParameters"]) == {"workflow"}, "unexpected build type/parameters")
    require(predicate["runDetails"]["builder"]["id"] == summary["builder"] and predicate["runDetails"]["metadata"]["invocationId"] == invocation, "predicate invocation differs")
    require(any(d.get("uri") == f"git+{uri}@{workflow['ref']}" and d.get("digest", {}).get("gitCommit") == source_run["head_sha"] for d in definition["resolvedDependencies"]), "source dependency differs")
    require(any(s.get("digest", {}).get("sha256") == digest(path.read_bytes()) for s in statement["subject"]), "upstream subject differs")
    verify_workflow_identity(builder)


def unpack(data):
    require(len(data) <= MAX_BYTES, "archive too large")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require(sum(e.file_size for e in archive.infolist()) <= MAX_BYTES, "expanded archive too large")
        result = {}
        for entry in archive.infolist():
            require(not entry.is_dir() and entry.filename not in result and re.fullmatch(r"[A-Za-z0-9_.-]+", entry.filename), "unexpected archive entry")
            result[entry.filename] = archive.read(entry)
        return result


def download_asset(repository, asset):
    require(0 < asset["size"] <= MAX_BYTES, "invalid asset size")
    data = run("gh", "api", "--hostname", "github.com", "-H", "Accept: application/octet-stream", f"repos/{repository}/releases/assets/{asset['id']}")
    require(len(data) == asset["size"] and asset["digest"] == f"sha256:{digest(data)}", "release asset differs")
    return data


def staging_prefix(policy):
    return "bathysign"


def staging_product(policy):
    return "Bathysign"


def asset_prefix(value):
    settings = value.get("publishing", {})
    prefix = settings.get("asset_prefix")
    require(isinstance(prefix, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", prefix), "invalid asset prefix")
    return prefix


def public_names(manifest):
    tag = manifest['release']['tag_name']
    require(re.fullmatch(r'(?:git-|v)[A-Za-z0-9_.+\-]{1,150}', tag), 'unsafe release tag')
    names = {f'{asset_prefix(manifest)}-{tag}-{profile}.{kind}' for profile in manifest['version_codes'] for kind in ('apk', 'aab')}
    names.add('version_code.txt')
    if not manifest['release']['prerelease']:
        names.add('version-info.txt')
    return names


def evidence_name(manifest):
    public_names(manifest)
    return f"{asset_prefix(manifest)}-{manifest['release']['tag_name']}-signing-evidence.zip"


def evidence_files(data):
    require(len(data) <= MAX_BYTES, 'evidence archive too large')
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = archive.infolist()
        require(0 < len(entries) <= 128 and len({e.filename for e in entries}) == len(entries), 'duplicate/excessive evidence entries')
        require(sum(e.file_size for e in entries) <= MAX_BYTES, 'expanded evidence too large')
        for entry in entries:
            require(re.fullmatch(r'[A-Za-z0-9_.+\-]{1,220}', entry.filename) and entry.filename not in ('.', '..')
                and not entry.is_dir() and not (entry.flag_bits & 1)
                and (entry.external_attr >> 16) & 0o170000 != 0o120000
                and entry.compress_type in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED), 'unsafe evidence entry')
        return {entry.filename: archive.read(entry) for entry in entries}


def compact_publication(files, manifest):
    """Package authenticated files; the archive retains the original signed manifest/bundle."""
    public = public_names(manifest)
    require(set(files) == set(manifest['assets']) | {'release-manifest.json', 'final.sigstore.json'}, 'incomplete release evidence')
    require(public <= set(files), 'missing public downloads')
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name in sorted(set(files) - public):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])
    data = output.getvalue()
    require(len(data) <= MAX_BYTES, 'evidence archive too large')
    return {**{name: files[name] for name in public}, evidence_name(manifest): data}


def published_evidence(policy, source_run, releases):
    marker = f"Verified Android signing; source run {source_run['id']}/{source_run['run_attempt']}; commit {source_run['head_sha']}; policy {policy['policy_hash']}"
    matches = [release for release in releases if not release['draft'] and release.get('body', '').split('\n', 1)[0] == marker]
    require(len(matches) <= 1, 'ambiguous published signing evidence')
    if not matches:
        return None
    release = matches[0]
    require(release['target_commitish'] == source_run['head_sha'], 'published source differs')
    assets = rows(f"repos/{policy['repository']}/releases/{release['id']}/assets")
    by_name = {a['name']: a for a in assets}
    require(len(by_name) == len(assets), 'duplicate published asset')
    name = f"{asset_prefix(policy)}-{release['tag_name']}-signing-evidence.zip"
    if name not in by_name:
        return None
    evidence = evidence_files(download_asset(policy['repository'], by_name[name]))
    manifest = load(evidence['release-manifest.json'])
    require(manifest['repository_id'] == policy['repository_id'] and manifest['policy_hash'] == policy['policy_hash']
        and manifest['source']['run_id'] == source_run['id'] and manifest['source']['attempt'] == source_run['run_attempt']
        and manifest['source']['commit'] == source_run['head_sha'] and manifest['release']['tag_name'] == release['tag_name'], 'published transaction differs')
    require(set(evidence) == (set(manifest['assets']) | {'release-manifest.json', 'final.sigstore.json'}) - public_names(manifest), 'published evidence set differs')
    return release, manifest, evidence, by_name


def recover_published(policy, source_run, releases, publication=None):
    publication = publication or published_evidence(policy, source_run, releases)
    if publication is None:
        return {}
    release, manifest, evidence, by_name = publication
    found = {}
    for profile in sorted(policy['profiles']):
        envelope = evidence[f'{profile}-signing-receipt.dsse.json']
        receipt = verify_receipt(envelope, policy)
        validate_transaction(receipt, policy, source_run, profile)
        files = {'signing-receipt.dsse.json': envelope, 'signing-receipt.json': evidence[f'{profile}-signing-receipt.json']}
        require(load(files['signing-receipt.json']) == receipt, 'plain receipt differs')
        names = [output['name'] for output in receipt['outputs']]
        require(len(set(names)) == len(names) and {'app-signed.apk', 'app-signed.aab', 'apk-lineage.bin', 'code_transparency_signed.jwt', 'transparency-certificate.der', 'unsigned-apk.sigstore.json', 'unsigned-aab.sigstore.json'} <= set(names), 'missing/duplicate published signing output')
        require(all(re.fullmatch(r'[A-Za-z0-9_.-]+', name) and name not in ('.', '..') for name in names), 'unsafe published signing output')
        for output in receipt['outputs']:
            output_name = output['name']
            if output_name in ('app-signed.apk', 'app-signed.aab'):
                published_name = f"{asset_prefix(policy)}-{release['tag_name']}-{profile}.{output_name.rsplit('.', 1)[1]}"
                require(published_name in by_name, 'published Android output missing')
                data = download_asset(policy['repository'], by_name[published_name])
            else:
                key = f'{profile}-{output_name}'
                if key not in evidence and output_name in ('unsigned-apk.sigstore.json', 'unsigned-aab.sigstore.json'):
                    key = f'provenance-{profile}.json'
                require(key in evidence, 'published signing output missing')
                data = evidence[key]
            require(len(data) == output['bytes'] and digest(data) == output['sha256'], 'published signing output differs')
            files[output_name] = data
        verify_trust_evidence(receipt, files, policy)
        found[profile] = (receipt, files)
    return found


def wait_staging(policy, source_run, timeout):
    pending = set(policy["profiles"])
    found = {}
    deadline = time.monotonic() + timeout
    while pending:
        releases = rows(f"repos/{policy['repository']}/releases")
        for profile in sorted(pending):
            job = f"v2-{policy['repository_id']}-{source_run['id']}-{source_run['run_attempt']}-{profile}-{policy['policy_hash']}"
            matches = [r for r in releases if r["tag_name"] == f"{staging_prefix(policy)}/{job}"]
            require(len(matches) <= 1, "ambiguous staging release")
            if not matches:
                continue
            release = matches[0]
            require(release["draft"] and release["target_commitish"] == source_run["head_sha"] and release["body"] == f"{staging_product(policy)} job {job}; commit {source_run['head_sha']}", "unmanaged staging release")
            assets = rows(f"repos/{policy['repository']}/releases/{release['id']}/assets")
            require(len({a['name'] for a in assets}) == len(assets), "duplicate asset")
            by_name = {a["name"]: a for a in assets}
            if "signing-receipt.dsse.json" not in by_name:
                continue
            envelope = download_asset(policy["repository"], by_name["signing-receipt.dsse.json"])
            receipt = verify_receipt(envelope, policy)
            validate_transaction(receipt, policy, source_run, profile)
            names = [o["name"] for o in receipt["outputs"]]
            require(len(set(names)) == len(names) and {"app-signed.apk", "app-signed.aab", "apk-lineage.bin", "code_transparency_signed.jwt", "transparency-certificate.der", "unsigned-apk.sigstore.json", "unsigned-aab.sigstore.json"} <= set(names), "missing/duplicate output")
            require(all(re.fullmatch(r"[A-Za-z0-9_.-]+", n) and n not in (".", "..") for n in names), "unsafe output name")
            if not set(names + ["signing-receipt.json"]) <= set(by_name):
                continue
            files = {n: download_asset(policy["repository"], by_name[n]) for n in names}
            for output in receipt["outputs"]:
                require(len(files[output["name"]]) == output["bytes"] and digest(files[output["name"]]) == output["sha256"], "signed output differs")
            plain = download_asset(policy["repository"], by_name["signing-receipt.json"])
            require(load(plain) == receipt, "plain receipt differs")
            files.update({"signing-receipt.dsse.json": envelope, "signing-receipt.json": plain})
            verify_trust_evidence(receipt, files, policy)
            found[profile] = (receipt, files)
        if pending - found.keys():
            recovered = recover_published(policy, source_run, releases)
            for profile in pending - found.keys():
                if profile in recovered:
                    found[profile] = recovered[profile]
        pending -= found.keys()
        if pending:
            require(time.monotonic() < deadline, "timed out waiting for signing transactions")
            time.sleep(min(15, max(0, deadline - time.monotonic())))
    return found


def unsigned_files(policy, source_run, receipt):
    result = {}
    for kind in ("apk", "aab"):
        meta = receipt["artifacts"][kind]
        actual = api(f"repos/{policy['repository']}/actions/artifacts/{meta['id']}")
        require(all(actual.get(k) == meta.get(k) for k in ("id", "name", "digest", "workflow_run")) and not actual["expired"], "input artifact metadata changed")
        require(meta["workflow_run"]["id"] == source_run["id"] and meta["workflow_run"]["head_sha"] == source_run["head_sha"] and meta["workflow_run"]["repository_id"] == policy["repository_id"], "input artifact run differs")
        require(actual["size_in_bytes"] <= MAX_BYTES, "input archive too large")
        archive = run("gh", "api", "--hostname", "github.com", f"repos/{policy['repository']}/actions/artifacts/{meta['id']}/zip")
        require(meta["digest"] == f"sha256:{digest(archive)}", "input archive digest differs")
        files = unpack(archive)
        data = files[f"app.{kind}"]
        require(digest(data) == receipt["inputs"][kind], "unsigned input digest differs")
        result[kind] = data
    return result


def source_tree_digest(data):
    # Gitiles regenerates tar member mtimes per download. Pin every source path
    # and its exact content instead of trusting mutable archive metadata.
    require(len(data) <= MAX_BYTES, "source archive too large")
    contents, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            require(name and not name.startswith("/") and "\\" not in name and all(p not in ("", ".", "..") for p in name.split("/")), "unsafe source path")
            require(name not in seen and len(seen) < 20_000, "duplicate/excessive source entries")
            seen.add(name)
            require(member.isdir() or member.isfile(), "unsupported source entry")
            total += member.size
            require(0 <= member.size <= MAX_BYTES and total <= MAX_BYTES, "expanded source archive too large")
            if member.isfile():
                content = archive.extractfile(member).read(member.size + 1)
                require(len(content) == member.size, "truncated source entry")
                contents[name] = digest(content)
    require(contents, "empty source archive")
    return digest(json_bytes(contents))


def download_pinned(url, sha256, path, source_tree=False):
    require(url.startswith("https://") and valid_hash(sha256), "invalid tool pin")
    if not path.exists():
        with urllib.request.urlopen(url, timeout=120) as response:
            data = response.read(MAX_BYTES + 1)
        actual = source_tree_digest(data) if source_tree else digest(data)
        require(len(data) <= MAX_BYTES and actual == sha256, "tool download differs")
        path.write_bytes(data)
    data = path.read_bytes()
    require((source_tree_digest(data) if source_tree else digest(data)) == sha256, "cached tool differs")


def preserve_payload(unsigned, signed, additions):
    with zipfile.ZipFile(io.BytesIO(unsigned)) as before, zipfile.ZipFile(io.BytesIO(signed)) as after:
        require(len(before.namelist()) == len(set(before.namelist())) and len(after.namelist()) == len(set(after.namelist())), "duplicate Android ZIP entry")
        require(set(before.namelist()) <= set(after.namelist()) and set(after.namelist()) - set(before.namelist()) <= additions, "unexpected signing transformation")
        require(all(before.read(name) == after.read(name) for name in before.namelist()), "Android payload changed during signing")


def android_verify(root, files, receipt, tool_dir):
    # Tools and Reference.java are trusted, reviewed parts of this helper checkout.
    for name, data in files.items():
        (root / name).write_bytes(data)
    keys = receipt["keys"]
    require(digest(files["apk-lineage.bin"]) == receipt["lineage"]["sha256"], "lineage file differs")
    with zipfile.ZipFile(io.BytesIO(files["app-signed.apk"])) as apk_zip, zipfile.ZipFile(io.BytesIO(files["app-signed.aab"])) as aab_zip:
        require(apk_zip.read("META-INF/code_transparency_signed.jwt") == aab_zip.read("BUNDLE-METADATA/com.android.tools.build.bundletool/code_transparency_signed.jwt") == files["code_transparency_signed.jwt"], "transparency JWTs differ")
    apk = root / "app-signed.apk"
    for sdk in (24, 28, 32, 33, 36, 37):
        selected = keys["original"] if sdk < receipt["rotation_min_sdk"] else keys["classical"]
        if sdk == 37 and keys["hybrid"]:
            selected = keys["hybrid"]["rsa"]
        classpath = tool_dir / "classes" if sdk >= 37 else f"{tool_dir / 'legacy'}{os.pathsep}{tool_dir / 'apksig-legacy.jar'}"
        run("java", "-cp", classpath, "Reference", "apk", apk, str(sdk), selected)
    run("java", "-cp", tool_dir / "classes", "Reference", "lineage", root / "apk-lineage.bin", str(len(receipt["lineage"]["certificates"])), ",".join(receipt["lineage"]["certificates"]))
    require(digest(files["transparency-certificate.der"]) == keys["transparency"], "transparency certificate differs")
    run("java", "-jar", tool_dir / "bundletool.jar", "validate", f"--bundle={root / 'app-signed.aab'}")
    cert_digest = run("keytool", "-printcert", "-jarfile", root / "app-signed.aab").decode()
    require(keys["upload"].upper() in re.sub(r"[^A-Z0-9]", "", cert_digest.upper()), "AAB upload certificate differs")
    # Trust only the independently pinned upload certificate, not the appliance's receipt alone.
    pem = run("keytool", "-printcert", "-rfc", "-jarfile", root / "app-signed.aab")
    (root / "upload.pem").write_bytes(pem)
    run("keytool", "-importcert", "-noprompt", "-alias", "upload", "-file", root / "upload.pem", "-keystore", root / "trust.p12", "-storepass", "verification-only")
    run("jarsigner", "-verify", "-strict", "-keystore", root / "trust.p12", "-storepass", "verification-only", root / "app-signed.aab", "upload")
    apk_zip = root / "transparency-apks.zip"
    with zipfile.ZipFile(apk_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.write(apk, "base.apk")
    for mode, flag, path in (("bundle", "bundle", root / "app-signed.aab"), ("apk", "apk-zip", apk_zip)):
        run("java", "-jar", tool_dir / "bundletool.jar", "check-transparency", f"--mode={mode}", f"--{flag}={path}", f"--transparency-key-certificate={root / 'transparency-certificate.der'}")
    apk_zip.unlink()


def prepare_tools(tool_dir):
    tool_dir.mkdir(parents=True, exist_ok=True)
    here = Path(__file__).parent
    pins = load((here / "signer-toolchain-pins.json").read_bytes())
    for kind, name in (("bundletool", "bundletool.jar"), ("apksig_legacy", "apksig-legacy.jar"), ("apksig_source", "apksig-source.tar.gz")):
        is_source = kind == "apksig_source"
        download_pinned(pins[kind + "_url"], pins[kind + ("_tree_sha256" if is_source else "_sha256")], tool_dir / name, source_tree=is_source)
    source = tool_dir / "source"
    source.mkdir(exist_ok=True)
    with tarfile.open(tool_dir / "apksig-source.tar.gz") as archive:
        require(sum(m.size for m in archive.getmembers()) < MAX_BYTES, "source archive too large")
        archive.extractall(source, filter="data")
    classes, legacy = tool_dir / "classes", tool_dir / "legacy"
    classes.mkdir(exist_ok=True)
    legacy.mkdir(exist_ok=True)
    sources = [str(p.resolve()) for p in (source / "src/main/java").rglob("*.java") if "/kms/aws/" not in str(p) and "/kms/gcp/" not in str(p)]
    sources.append(str((here / "Reference.java").resolve()))
    arguments = tool_dir / "sources.txt"
    arguments.write_text("\n".join(sources))
    run("javac", "-d", classes, f"@{arguments}")
    run("javac", "-cp", tool_dir / "apksig-legacy.jar", "-d", legacy, here / "Reference.java")


def validate_finalizer_context(metadata):
    require(os.environ["GITHUB_EVENT_NAME"] == "workflow_dispatch" and os.environ["GITHUB_REF"] == f"refs/heads/{metadata['default_branch']}", "finalizer must be dispatched from the default branch")


def final_predicate(policy, source_run_id, source_attempt, metadata, summaries, dependencies):
    validate_finalizer_context(metadata)
    inputs = {"source_run": str(source_run_id), "source_attempt": str(source_attempt)}
    event = load(Path(os.environ["GITHUB_EVENT_PATH"]).read_bytes())
    require(event.get("inputs") == inputs, "finalizer inputs differ from control-plane event")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "finalizer must use a hosted runner")
    finalizer = os.environ["GITHUB_WORKFLOW_REF"]
    require(finalizer == f"{policy['repository']}/.github/workflows/bathysign-release.yml@{os.environ['GITHUB_REF']}", "unexpected finalizer caller")
    repository_uri = f"https://github.com/{policy['repository']}"
    trusted = policy["finalizer"]
    verify_workflow_identity(trusted)
    expected = f"{trusted['repository']}/{trusted['workflow']}@{trusted['refs'][0]}"
    require(os.environ.get("BATHYSIGN_JOB_WORKFLOW_REF") == expected, "untrusted finalizer job identity")
    signer_commit = os.environ.get("BATHYSIGN_JOB_WORKFLOW_SHA", "")
    require(valid_hash(signer_commit, 40), "missing platform finalizer revision")
    signer_uri = "https://github.com/" + expected
    dependencies = [{"uri": f"git+https://github.com/{trusted['repository']}@{trusted['refs'][0]}", "digest": {"gitCommit": signer_commit}}, *dependencies]
    # GitHub's attestation API requires its workflow source as the first entry.
    dependencies = [{"uri": f"git+{repository_uri}@{os.environ['GITHUB_REF']}", "digest": {"gitCommit": os.environ["GITHUB_SHA"]}}, *dependencies]
    github = {"event_name": "workflow_dispatch", "repository_id": str(metadata["id"]), "repository_owner_id": str(metadata["owner"]["id"]), "runner_environment": "github-hosted"}
    return {"buildDefinition": {"buildType": BUILD_TYPE, "externalParameters": {"workflow": {"repository": repository_uri, "ref": os.environ["GITHUB_REF"], "path": ".github/workflows/bathysign-release.yml"}, "inputs": inputs}, "internalParameters": {"github": github, "finalizerWorkflow": signer_uri, "finalizerCommit": signer_commit, "signingTransactions": summaries}, "resolvedDependencies": dependencies}, "runDetails": {"builder": {"id": signer_uri}, "metadata": {"invocationId": f"{repository_uri}/actions/runs/{os.environ['GITHUB_RUN_ID']}/attempts/{os.environ['GITHUB_RUN_ATTEMPT']}"}}}


def prepare(policy_path, source_run_id, source_attempt, out, tool_dir):
    policy = load(policy_path.read_bytes())
    validate_policy(policy)
    require(os.environ["GITHUB_REPOSITORY"] == policy["repository"], "finalizer repository differs")
    source_run = api(f"repos/{policy['repository']}/actions/runs/{source_run_id}/attempts/{source_attempt}")
    metadata = api(f"repos/{policy['repository']}")
    validate_finalizer_context(metadata)
    require(metadata["id"] == policy["repository_id"] and metadata["visibility"] == policy["visibility"], "repository identity changed")
    require(source_run["id"] == source_run_id and source_run["run_attempt"] == source_attempt and source_run["status"] == "completed" and source_run["conclusion"] == "success", "unsuccessful source run")
    require(source_run["event"] == "push" and source_run["head_repository"]["id"] == policy["repository_id"], "ineligible source run")
    require(source_run["path"] in policy["callers"], "ineligible caller workflow")
    out.mkdir(exist_ok=False, parents=True)
    prepare_tools(tool_dir)
    transactions = wait_staging(policy, source_run, 1800)
    dependencies, summaries = [], {}
    for profile, (receipt, files) in transactions.items():
        root = out / profile
        root.mkdir()
        inputs = unsigned_files(policy, source_run, receipt)
        for kind, data in inputs.items():
            original = root / f"app-unsigned.{kind}"
            original.write_bytes(data)
            bundle = root / f"unsigned-{kind}.sigstore.json"
            bundle.write_bytes(files[bundle.name])
            verify_provenance(original, bundle, policy, source_run, receipt["provenance"][kind])
            dependencies.append({"uri": f"urn:bathysign:unsigned:{profile}:{kind}", "digest": {"sha256": digest(data)}})
            dependencies.append({"uri": f"urn:bathysign:unsigned-provenance:{profile}:{kind}", "digest": {"sha256": digest(files[bundle.name])}})
            summary = receipt["provenance"][kind]
            dependencies.append({"uri": "git+" + summary["builder"], "digest": {"gitCommit": summary["builder_commit"]}})
        preserve_payload(inputs["apk"], files["app-signed.apk"], {"META-INF/code_transparency_signed.jwt"})
        preserve_payload(inputs["aab"], files["app-signed.aab"], {"BUNDLE-METADATA/com.android.tools.build.bundletool/code_transparency_signed.jwt", "META-INF/MANIFEST.MF", "META-INF/SIGNER.SF", "META-INF/SIGNER.RSA"})
        android_verify(root, files, receipt, tool_dir)
        dependencies.append({"uri": f"urn:bathysign:receipt:{profile}", "digest": {"sha256": digest(files['signing-receipt.dsse.json'])}})
        summaries[profile] = {"job_id": receipt["job"]["id"], "receipt_sha256": digest(files["signing-receipt.dsse.json"]), "keys": receipt["keys"], "lineage": receipt["lineage"]}
    dependencies.extend([{"uri": f"git+https://github.com/{policy['repository']}", "digest": {"gitCommit": source_run["head_sha"]}}, {"uri": "urn:bathysign:policy", "digest": {"sha256": policy["policy_hash"]}}, {"uri": "urn:bathysign:implementation", "digest": {"gitCommit": policy["signer_revision"]}}])
    predicate = final_predicate(policy, source_run_id, source_attempt, metadata, summaries, dependencies)
    (out / "predicate.json").write_bytes(json_bytes(predicate))
    (out / "verification.json").write_bytes(json_bytes({"version": 1, "source_run": source_run_id, "source_attempt": source_attempt, "source_commit": source_run["head_sha"], "profiles": summaries}))


def upload(repo, release_id, name, data, content_type="application/octet-stream"):
    existing = [a for a in rows(f"repos/{repo}/releases/{release_id}/assets") if a["name"] == name]
    require(len(existing) <= 1, "duplicate final release asset")
    if existing:
        if existing[0].get("state") == "starter" and existing[0].get("digest") is None:
            run("gh", "api", "--hostname", "github.com", "--method", "DELETE", f"repos/{repo}/releases/assets/{existing[0]['id']}")
        else:
            require(existing[0].get("state") == "uploaded" and existing[0]["digest"] == f"sha256:{digest(data)}" and existing[0]["size"] == len(data), "conflicting final release asset")
            return
    with tempfile.NamedTemporaryFile() as tmp:
        tmp.write(data)
        tmp.flush()
        from urllib.parse import quote
        run("gh", "api", "--hostname", "github.com", "--method", "POST", "-H", f"Content-Type: {content_type}", f"https://uploads.github.com/repos/{repo}/releases/{release_id}/assets?name={quote(name, safe='')}", "--input", tmp.name)


def verify_final_bundle(out, policy_path):
    policy = load(policy_path.read_bytes())
    validate_policy(policy)
    repo = os.environ["GITHUB_REPOSITORY"]
    require(repo == policy["repository"], "final bundle repository differs from policy")
    finalizer = policy["finalizer"]
    metadata = load((out / "verification.json").read_bytes())
    require(set(metadata["profiles"]) == set(policy["profiles"]), "profile set differs from policy")
    # Authenticate all four outputs without creating another GitHub release.
    for profile in metadata["profiles"]:
        for kind in ("apk", "aab"):
            verified = load(run("gh", "attestation", "verify", out / profile / f"app-signed.{kind}",
                "--bundle", out / "final.sigstore.json", "--repo", repo,
                "--signer-workflow", f"{finalizer['repository']}/{finalizer['workflow']}",
                "--source-digest", os.environ["GITHUB_SHA"], "--source-ref", os.environ["GITHUB_REF"],
                "--deny-self-hosted-runners", "--format", "json"))
            require(len(verified) == 1, "ambiguous final bundle provenance")
            verify_finalizer_certificate(policy, verified[0]["verificationResult"]["signature"]["certificate"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify-bundle"))
    parser.add_argument("--policy", type=Path)
    parser.add_argument("--source-run", type=int)
    parser.add_argument("--source-attempt", type=int)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--tools", type=Path)
    args = parser.parse_args()
    if args.command == "prepare":
        require(args.policy and args.source_run and args.source_attempt and args.tools, "policy/source run/attempt/tools required")
        prepare(args.policy, args.source_run, args.source_attempt, args.out, args.tools.resolve())
    else:
        require(args.policy, "central policy snapshot required")
        verify_final_bundle(args.out, args.policy)


if __name__ == "__main__":
    main()
