import unittest, json, base64, hashlib, tempfile, pathlib, datetime, copy, subprocess, sys, os, struct
from cryptography import x509
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID,ObjectIdentifier
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import ed25519,ec,rsa
from ocsp_staple_review import audit
from ocsp_staple_review.common import ReviewError,load,read
UTC=datetime.timezone.utc
def enc(b):return base64.b64encode(b).decode()
def url(b):return base64.urlsafe_b64encode(b).decode().rstrip('=')
def pemkey(k):return k.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo).decode()
def certs(leaf_extensions=(),issuer_extensions=()):
    now=datetime.datetime.now(UTC).replace(microsecond=0);issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048);leaf_key=ed25519.Ed25519PrivateKey.generate()
    subject=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Synthetic Review CA')])
    ku=x509.KeyUsage(True,False,False,False,False,True,True,False,False)
    builder=x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(issuer_key.public_key()).serial_number(1).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=30)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).add_extension(ku,True).add_extension(x509.SubjectKeyIdentifier.from_public_key(issuer_key.public_key()),False)
    for ext,critical in issuer_extensions:builder=builder.add_extension(ext,critical)
    issuer=builder.sign(issuer_key,hashes.SHA256())
    builder=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'synthetic.invalid')])).issuer_name(subject).public_key(leaf_key.public_key()).serial_number(10).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=3)).add_extension(x509.BasicConstraints(ca=False,path_length=None),True).add_extension(x509.KeyUsage(True,False,False,False,False,False,False,False,False),True)
    for ext,critical in leaf_extensions:builder=builder.add_extension(ext,critical)
    leaf=builder.sign(issuer_key,hashes.SHA256());return now,issuer_key,issuer,leaf_key,leaf
def cpem(c):return c.public_bytes(serialization.Encoding.PEM).decode()
def save_example(d):
    if os.environ.get('GENERATE_REVIEW_EXAMPLES')!='1':return
    out=pathlib.Path(__file__).resolve().parents[1]/'examples';out.mkdir(exist_ok=True)
    (out/'valid.json').write_text(json.dumps(d,indent=2)+'\n')
class CommonTests(unittest.TestCase):
    def test_duplicate_and_nonfinite_input(self):
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}',b'[]'):
            with self.assertRaises(ReviewError):load(raw)
    def test_input_symlink_and_fifo(self):
        with tempfile.TemporaryDirectory() as t:
            p=pathlib.Path(t);(p/'file').write_text('x');(p/'link').symlink_to(p/'file');os.mkfifo(p/'pipe')
            for q in (p/'link',p/'pipe'):
                with self.assertRaises((ReviewError,OSError)):read(str(q))
    def test_missing_fields_and_cli_exit(self):
        with self.assertRaises((ReviewError,KeyError)):audit({})
        proc=subprocess.run([sys.executable,'-m','ocsp_staple_review','-'],input=b'{}',capture_output=True,timeout=10)
        self.assertEqual(proc.returncode,1);self.assertEqual(json.loads(proc.stdout)['status'],'FAIL');self.assertFalse(json.loads(proc.stdout)['complete'])

class OcspTests(unittest.TestCase):
    def setUp(self):
        self.now,self.key,self.issuer,_,self.leaf=certs();self.d={'issuer_pem':cpem(self.issuer),'issuer_sha256':self.issuer.fingerprint(hashes.SHA256()).hex(),'certificate_pem':cpem(self.leaf),'max_age_seconds':3600,'response_der':self.response()};self.d['now']=datetime.datetime.now(UTC).isoformat()
    def response(self,status=ocsp.OCSPCertStatus.GOOD,nonce=None,extra=None):
        b=ocsp.OCSPResponseBuilder().add_response(self.leaf,self.issuer,hashes.SHA256(),status,self.now-datetime.timedelta(minutes=1),self.now+datetime.timedelta(hours=1),self.now-datetime.timedelta(minutes=2) if status==ocsp.OCSPCertStatus.REVOKED else None,None).responder_id(ocsp.OCSPResponderEncoding.HASH,self.issuer)
        if nonce:b=b.add_extension(x509.OCSPNonce(nonce),False)
        if extra:b=b.add_extension(extra,True)
        return enc(b.sign(self.key,hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    def test_valid_good_revoked_nonce(self):
        self.assertTrue(audit(self.d)['verified']);save_example(self.d);self.d['response_der']=self.response(ocsp.OCSPCertStatus.REVOKED);self.assertEqual(audit(self.d)['status'],'FAIL');self.d['response_der']=self.response(nonce=b'syntheticnonce');self.d['nonce']=url(b'syntheticnonce');self.assertTrue(audit(self.d)['verified'])
    def test_tamper_pin_stale_unknown_extensions_and_nonce(self):
        raw=bytearray(base64.b64decode(self.d['response_der']));raw[-1]^=1
        mutations=[lambda d:d.update(response_der=enc(raw)),lambda d:d.update(issuer_sha256='0'*64),lambda d:d.update(now=(self.now+datetime.timedelta(hours=2)).isoformat()),lambda d:d.update(response_der=self.response(ocsp.OCSPCertStatus.UNKNOWN)),lambda d:d.update(response_der=self.response(extra=x509.UnrecognizedExtension(ObjectIdentifier('1.2.3.4.5'),b'\x05\x00'))),lambda d:d.update(nonce=url(b'notmatching'))]
        for change in mutations:
            d=copy.deepcopy(self.d);change(d)
            with self.assertRaises(ReviewError):audit(d)

if __name__=="__main__":unittest.main()
