import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location('trust_evidence', ROOT / 'scripts/trust_evidence.py')
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)

class TrustEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'tests/fixtures/trust-checkpoint.json').read_bytes()
        self.checkpoint = json.loads(self.raw)
        self.binding = json.loads((ROOT / 'tests/fixtures/trust-binding.json').read_bytes())

    def test_offline_evidence_matches_rust_binding(self):
        self.assertEqual(verifier.verify(self.raw, {'trust':self.binding}, self.checkpoint['authority']), self.binding)

    def test_publication_requires_provenance_to_use_the_authenticated_target(self):
        spec=importlib.util.spec_from_file_location('trust_release',ROOT/'scripts/signer-release.py')
        helper=importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        receipt={'trust':self.binding,'provenance':{kind:{'trust_root_sha256':self.binding['target_sha256']} for kind in ('apk','aab')}}
        policy={'version':4,'trust_authority':self.checkpoint['authority']}
        helper.verify_trust_evidence(receipt,{'trust-evidence.json':self.raw},policy)
        receipt['provenance']['apk']['trust_root_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'provenance trust root differs'):
            helper.verify_trust_evidence(receipt,{'trust-evidence.json':self.raw},policy)

    def test_tampering_and_incomplete_authorization_fail(self):
        for field in ('target','metadata','binding','authority','partial'):
            with self.subTest(field=field):
                checkpoint=copy.deepcopy(self.checkpoint)
                binding=copy.deepcopy(self.binding)
                authority=copy.deepcopy(self.checkpoint['authority'])
                if field=='target': checkpoint['target']='Y29ycnVwdA=='
                elif field=='metadata': checkpoint['observations'][1]['bytes']='Y29ycnVwdA=='
                elif field=='binding': binding['generation']+=1
                elif field=='authority': authority['epoch']='b'*64
                elif field=='partial': checkpoint['usable']=False
                with self.assertRaises(Exception):
                    verifier.verify(json.dumps(checkpoint).encode(),{'trust':binding},authority)

if __name__ == '__main__':
    unittest.main()
