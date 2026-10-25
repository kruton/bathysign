"""Offline public Sigstore evidence verification using pinned python-tuf 6.0.

No HTTP client or private auditor access is used. Historical observations are
replayed at their acceptance time; publication does not require still-live TUF.
"""
import base64
import datetime
import hashlib
import json
from pathlib import Path
from urllib.parse import unquote


def verify(data, receipt, authority):
    from tuf.ngclient._internal.trusted_metadata_set import TrustedMetadataSet
    from tuf.ngclient.config import EnvelopeType

    def require(condition, message):
        if not condition:
            raise ValueError(message)

    def decode(value):
        return base64.b64decode(value, validate=True)

    def at(seconds):
        require(type(seconds) is int and seconds >= 0, 'invalid trust time')
        return datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)

    require(len(data) <= 24 * 1024 * 1024, 'oversized trust evidence')
    checkpoint = json.loads(data)
    fields = ['version', 'authority', 'generation', 'previous', 'verified_at', 'observations', 'target', 'usable']
    require(set(checkpoint) == set(fields), 'unexpected checkpoint fields')
    require(checkpoint['version'] == 1 and checkpoint['usable'] is True and checkpoint['generation'] > 0,
            'incomplete trust evidence')
    require(checkpoint['authority'] == authority, 'trust authority differs')
    root = Path(__file__).with_name('sigstore-root.json').read_bytes()
    require(authority['authority'] == 'sigstore-public' and authority['target'] == 'trusted_root.json'
            and authority['bootstrap_sha256'] == hashlib.sha256(root).hexdigest(), 'bootstrap differs')
    trusted = TrustedMetadataSet(root, EnvelopeType.METADATA)
    role_bytes = {}
    total = 0
    last = 0
    require(len(checkpoint['observations']) <= 16384, 'trust history too large')
    for observation in checkpoint['observations']:
        require(set(observation) == {'name', 'bytes', 'verified_at'}, 'unexpected observation fields')
        moment = observation['verified_at']
        require(last <= moment <= checkpoint['verified_at'], 'trust time regressed')
        last = moment
        trusted.reference_time = at(moment)
        name = observation['name']
        raw = decode(observation['bytes'])
        total += len(raw) + len(name.encode()) + 128
        require(total <= 16 * 1024 * 1024 and len(raw) <= 5_000_000, 'trust history too large')
        # The pinned library models one refresh. Retain authenticated floors
        # while removing descendants invalidated by a new refresh, matching
        # the Rust verifier's explicit transition rules.
        if name.startswith('root_history/') and name.endswith('.root.json'):
            version = int(name.removeprefix('root_history/').removesuffix('.root.json'))
            if version == trusted.root.version:
                require(raw == root, 'conflicting root version')
            else:
                trusted._trusted_set = {'root': trusted.root}
                trusted.update_root(raw)
                require(trusted.root.version == version, 'root filename differs')
                root = raw
                role_bytes.clear()
        elif name == 'timestamp.json':
            previous_snapshot = trusted.get('snapshot')
            trusted._trusted_set = {k: v for k, v in trusted._trusted_set.items() if k in ('root', 'timestamp')}
            trusted.update_timestamp(raw)
            if previous_snapshot is not None:
                trusted._trusted_set['snapshot'] = previous_snapshot
        elif name == 'snapshot.json':
            trusted._trusted_set = {k: v for k, v in trusted._trusted_set.items() if k in ('root', 'timestamp', 'snapshot')}
            trusted.update_snapshot(raw)
            role_bytes.clear()
        elif name == 'targets.json':
            trusted.update_targets(raw)
            role_bytes['targets'] = raw
        else:
            require(name.endswith('.json'), 'invalid role filename')
            role = unquote(name[:-5], errors='strict')
            parents = [parent for parent in role_bytes if trusted[parent].delegations
                       and role in trusted[parent].delegations.roles]
            accepted = False
            for parent in parents:
                try:
                    trusted.update_delegated_targets(raw, role, parent)
                    accepted = True
                    break
                except Exception:
                    continue
            require(accepted, 'unauthorized delegated metadata')
            role_bytes[role] = raw
    moment = at(checkpoint['verified_at'])
    trusted.reference_time = moment
    trusted._check_final_timestamp()
    trusted._check_final_snapshot()
    require(not trusted.root.is_expired(moment), 'expired root')
    require(trusted.snapshot.meta['targets.json'].version == trusted.targets.version, 'incomplete targets authorization')
    queue = [('targets', 'root')]
    seen = set()
    expiry = min(trusted.root.expires, trusted.timestamp.expires, trusted.snapshot.expires)
    target = None
    while queue:
        role, parent = queue.pop(0)
        if role in seen:
            continue
        seen.add(role)
        require(len(seen) <= 32, 'delegation limit exceeded')
        require(role in role_bytes, 'required delegated metadata missing')
        # Reauthenticate each parent edge, including roles with multiple parents.
        trusted.update_delegated_targets(role_bytes[role], role, parent)
        metadata = trusted[role]
        require(not metadata.is_expired(moment), 'expired targets')
        expiry = min(expiry, metadata.expires)
        target = metadata.targets.get(authority['target'])
        if target is not None:
            break
        children = []
        if metadata.delegations:
            for child in metadata.delegations.roles.values():
                if child.is_delegated_path(authority['target']):
                    children.append((child.name, role))
                    if child.terminating:
                        queue.clear()
                        break
        queue = children + queue
    require(target is not None, 'trust target is unauthorized')
    target_bytes = decode(checkpoint['target'])
    require(len(target_bytes) <= 1024 * 1024, 'oversized trust target')
    target.verify_length_and_hashes(target_bytes)
    # Match Rust struct serialization, independent of pretty-printing in transit.
    authority_fields = ['authority', 'bootstrap_sha256', 'epoch', 'target']
    checkpoint['authority'] = {k: authority[k] for k in authority_fields}
    checkpoint['observations'] = [{k: o[k] for k in ['name', 'bytes', 'verified_at']} for o in checkpoint['observations']]
    encoded = json.dumps({k: checkpoint[k] for k in fields}, separators=(',', ':'), ensure_ascii=False).encode()
    binding = {'authority': authority, 'generation': checkpoint['generation'],
               'checkpoint_sha256': hashlib.sha256(encoded).hexdigest(),
               'target_sha256': hashlib.sha256(target_bytes).hexdigest(), 'valid_until': int(expiry.timestamp())}
    require(receipt['trust'] == binding, 'receipt trust binding differs')
    return binding
