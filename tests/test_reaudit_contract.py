from cryptography.hazmat.primitives.asymmetric import padding
import unittest,json,sys,subprocess,copy,base64,hashlib,datetime
from ocsp_staple_review import audit
from ocsp_staple_review.common import ReviewError,load
import test_review as fixtures
def reject(test,d):
    with test.assertRaises(ReviewError):audit(d)
    p=subprocess.run([sys.executable,'-m','ocsp_staple_review','-'],input=json.dumps(d).encode(),capture_output=True,timeout=10)
    out=json.loads(p.stdout);test.assertEqual(p.returncode,1);test.assertEqual(out['status'],'FAIL');test.assertFalse(out['complete']);test.assertFalse(out.get('verified',False))
class FiniteInputTests(unittest.TestCase):
    def test_exponent_overflow_rejected_api_and_cli(self):
        for raw in (b'{"x":1e999}',b'{"x":[-1e999]}'):
            with self.assertRaises(ReviewError):load(raw)
            p=subprocess.run([sys.executable,'-m','ocsp_staple_review','-'],input=raw,capture_output=True,timeout=10);out=json.loads(p.stdout)
            self.assertEqual(p.returncode,1);self.assertFalse(out['complete']);self.assertEqual(out['status'],'FAIL')
        self.assertEqual(load(b'{"x":1.25}'),{'x':1.25})
    def test_unknown_fields_error_does_not_echo_canary(self):
        canary='SYNTHETIC-PRIVATE-CANARY-cc94e6f3'
        with self.assertRaises(ReviewError) as e:audit({canary:canary})
        self.assertNotIn(canary,str(e.exception))
        p=subprocess.run([sys.executable,'-m','ocsp_staple_review','-'],input=json.dumps({canary:canary}).encode(),capture_output=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertNotIn(canary,p.stdout.decode()+p.stderr.decode())
class RevocationTimeTests(unittest.TestCase):
    def request(self,offset):
        t=fixtures.OcspTests();t.setUp();status_time=t.now-datetime.timedelta(minutes=1)
        response=fixtures.ocsp.OCSPResponseBuilder().add_response(t.leaf,t.issuer,fixtures.hashes.SHA256(),fixtures.ocsp.OCSPCertStatus.REVOKED,status_time,t.now+datetime.timedelta(hours=1),status_time+datetime.timedelta(seconds=offset),None).responder_id(fixtures.ocsp.OCSPResponderEncoding.HASH,t.issuer).sign(t.key,fixtures.hashes.SHA256())
        t.issuer.public_key().verify(response.signature,response.tbs_response_bytes,padding.PKCS1v15(),response.signature_hash_algorithm)
        return {**t.d,'response_der':fixtures.enc(response.public_bytes(fixtures.serialization.Encoding.DER)),'now':datetime.datetime.now(fixtures.UTC).isoformat()}
    def test_revocation_cannot_follow_status_time_api_cli(self):reject(self,self.request(1))
    def test_equal_and_earlier_revocation_keep_complete_status(self):
        for offset in (0,-1):
            r=audit(self.request(offset));self.assertEqual(r['status'],'FAIL');self.assertTrue(r['verified']);self.assertTrue(r['complete'])

class FilePlatformCapabilityTests(unittest.TestCase):
    def test_missing_or_unusable_file_flags_fail_closed(self):
        from unittest import mock
        from ocsp_staple_review.common import read
        from ocsp_staple_review import common
        for flag in ('O_NOFOLLOW','O_NONBLOCK'):
            for value in (None,0,'unusable'):
                with mock.patch.object(common.os,flag,value,create=True):
                    with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
            with mock.patch.object(common.os,flag,1,create=True):
                delattr(common.os,flag)
                with self.assertRaisesRegex(ReviewError,'flags unavailable'):read('synthetic-nonexistent-file')
