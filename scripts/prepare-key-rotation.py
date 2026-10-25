#!/usr/bin/env python3
"""Prepare an API-33 RSA rotation without modifying active configuration or stores."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


def require(condition, message):
    if not condition:
        raise ValueError(message)


def run(*args):
    # Do not echo commands, key bytes, or tool diagnostics containing configuration.
    result = subprocess.run([str(a) for a in args], capture_output=True)
    require(result.returncode == 0, f"{Path(str(args[0])).name} failed")
    return result.stdout


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(path, value):
    with path.open("x") as output:
        json.dump(value, output, indent=2)
        output.write("\n")


def repository(config, name):
    rows = [r for r in config["repositories"] if r["name"] == name]
    require(len(rows) == 1, "repository missing or ambiguous")
    return rows[0]


def policy_hash(config, name):
    """Must agree with the native exporter before producing a deployment policy."""
    repo = repository(config, name)
    roles = {repo["receipt_key"]}
    for profile in repo["profiles"].values():
        signing = profile["signing"]
        roles.update(signing[k] for k in ("original_key", "current_key", "upload_key", "transparency_key"))
        require(not signing.get("hybrid"), "classical rotation requires a non-hybrid profile")
    value = {"version": 4 if config.get("trust_authority") else 3, "repository": repo,
             "key_certificate_pins": {k: config["keys"][k]["fingerprint"] for k in roles},
             "max_artifact_bytes": config["max_artifact_bytes"],
             "max_lineage_bytes": config["max_lineage_bytes"]}
    if config.get("trust_authority"):
        value["trust_authority"] = config["trust_authority"]
    else:
        value["trust_root"] = config["trust_roots"][repo["visibility"]]
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode())


def without_paths(value):
    if isinstance(value, dict):
        return {k: without_paths(v) for k, v in value.items()}
    if isinstance(value, list):
        return [without_paths(v) for v in value]
    return "<path>" if isinstance(value, str) and value.startswith("/") else value


def prepare(args):
    offline = json.loads(args.config.read_bytes())
    deployment = json.loads(args.deployment_config.read_bytes())
    require(without_paths(offline) == without_paths(deployment), "offline/deployment settings differ beyond paths")
    require(re.fullmatch(r"[0-9a-f]{40}", args.signer_revision), "full deployed signer revision required")
    require(re.fullmatch(r"[a-zA-Z0-9_-]+", args.key_id), "invalid key role")
    require(args.guest_directory.is_absolute(), "absolute guest directory required")
    require(args.key_id not in offline["keys"], "replacement role already exists")
    require(args.rotation_min_sdk in (28, 33), "rotation SDK must be 28 or 33")
    current_revision = repository(offline, args.repository)["revision"]
    revision = args.revision if args.revision is not None else current_revision + 1
    require(revision > current_revision, "replacement revision must exceed the active revision")
    cert = run("openssl", "x509", "-in", args.certificate, "-outform", "DER")
    public = run("openssl", "x509", "-in", args.certificate, "-pubkey", "-noout")
    result = subprocess.run(["openssl", "pkey", "-pubin", "-text", "-noout"], input=public, capture_output=True)
    require(result.returncode == 0 and b"(4096 bit)" in result.stdout and b"Exponent: 65537 " in result.stdout,
            "replacement must be RSA-4096 with exponent 65537")
    public_der = subprocess.run(["openssl", "pkey", "-pubin", "-outform", "DER"], input=public, capture_output=True)
    require(public_der.returncode == 0, "invalid certificate public key")
    require(run("openssl", "pkey", "-in", args.key, "-pubout", "-outform", "DER") == public_der.stdout,
            "replacement key and certificate differ")
    fingerprint = digest(cert)
    require(all(k["fingerprint"] != fingerprint for k in offline["keys"].values()), "replacement certificate already configured")
    # No writes occur before basic preflight; never overwrite an earlier preparation.
    args.out.mkdir(mode=0o700)
    (args.out / "replacement-certificate.der").write_bytes(cert)
    (args.out / "replacement-certificate.pem").write_bytes(run("openssl", "x509", "-in", args.certificate, "-outform", "PEM"))
    candidate = copy.deepcopy(offline)
    guest = copy.deepcopy(deployment)
    candidate["keys"][args.key_id] = {"private_key": str(args.key.resolve()), "certificate": str(args.certificate.resolve()), "fingerprint": fingerprint}
    guest["keys"][args.key_id] = {"private_key": str(args.guest_directory / args.key.name), "certificate": str(args.guest_directory / args.certificate.name), "fingerprint": fingerprint}
    repo = repository(candidate, args.repository)
    deployed_repo = repository(guest, args.repository)
    repo["revision"] = revision
    deployed_repo["revision"] = repo["revision"]
    groups = {}
    for name, profile in repo["profiles"].items():
        signing = profile["signing"]
        require(not signing.get("hybrid"), "cannot replace an active hybrid identity")
        lineage = Path(signing["lineage"])
        require(digest(lineage.read_bytes()) == signing["lineage_sha256"], "input lineage hash differs")
        old = candidate["keys"][signing["current_key"]]
        group = (old["fingerprint"], signing["lineage_sha256"], signing.get("allow_rollback", False))
        if group not in groups:
            output = args.out / f"apk-lineage-{len(groups)}.bin"
            command = [args.admin, "append", "--input", lineage, "--old-key", old["private_key"],
                       "--old-cert", old["certificate"], "--new-cert", args.certificate,
                       "--out", output, "--max-bytes", candidate["max_lineage_bytes"]]
            if signing.get("allow_legacy_rsa_1024"):
                command.append("--legacy-old-rsa-1024")
            if signing.get("allow_rollback"):
                command.append("--allow-rollback")
            run(*command)
            groups[group] = output
        output = groups[group]
        updates = {"current_key": args.key_id, "rotation_min_sdk": args.rotation_min_sdk,
                   "lineage_sha256": digest(output.read_bytes())}
        signing.update(updates, lineage=str(output.resolve()))
        deployed_repo["profiles"][name]["signing"].update(updates, lineage=str(args.guest_directory / output.name))
    save(args.out / "config.offline.json", candidate)
    save(args.out / "config.deployment.json", guest)
    run(args.admin, "export-release-policy", "--config", args.out / "config.offline.json",
        "--repository", args.repository, "--signer-revision", args.signer_revision,
        "--out", args.out / "public-policy.offline.json")
    policy = json.loads((args.out / "public-policy.offline.json").read_bytes())
    require(policy["policy_hash"] == policy_hash(candidate, args.repository), "native policy hash disagrees; do not deploy")
    policy["policy_hash"] = policy_hash(guest, args.repository)
    save(args.out / "public-policy.json", policy)
    report = {"version": 1, "status": "prepared-not-activated", "repository": args.repository,
              "revision": repo["revision"], "policy_hash": policy["policy_hash"],
              "replacement_certificate_sha256": fingerprint, "rotation_min_sdk": args.rotation_min_sdk,
              "original_keys_retained": True, "source_config_sha256": digest(args.deployment_config.read_bytes()),
              "channels": {"github": "candidate-requires-verification", "play": "console-authorization-and-delivered-apk-tests-required",
                           "fdroid": "maintainer-authorization-reproducibility-and-legacy-updates-required"}}
    save(args.out / "preparation.json", report)
    print(json.dumps(report, indent=2))


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("config", "deployment-config", "key", "certificate", "admin", "out", "guest-directory"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--signer-revision", required=True)
    parser.add_argument("--key-id", default="apk-rsa4096")
    parser.add_argument("--rotation-min-sdk", type=int, choices=(28, 33), default=33)
    parser.add_argument("--revision", type=int, help="New policy revision; defaults to active revision + 1")
    prepare(parser.parse_args())


if __name__ == "__main__":
    main()
