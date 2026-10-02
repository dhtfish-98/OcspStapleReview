from .common import *
from .crypto import *
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtendedKeyUsageOID

def audit(d):
    fields(d,['issuer_pem','issuer_sha256','certificate_pem','response_der','now','max_age_seconds'],['nonce','responder_pem'])
    now=instant(d['now']);issuer=certificate(d['issuer_pem']);leaf=certificate(d['certificate_pem']);issuer_pair(leaf,issuer,now)
    need(issuer.fingerprint(hashes.SHA256()).hex()==string(d['issuer_sha256'],64),"pinned issuer mismatch")
    age=integer(d['max_age_seconds'],1,604800)
    raw=b64(d['response_der'],limit=1048576);ocsp_der(raw)
    try:r=ocsp.load_der_ocsp_response(raw)
    except ValueError:raise ReviewError("invalid OCSP response") from None
    need(r.response_status==ocsp.OCSPResponseStatus.SUCCESSFUL,"OCSP responder did not return successful evidence")
    responses=list(r.responses);need(len(responses)==1,"only one OCSP SingleResponse supported");single=responses[0]
    need(single.serial_number==leaf.serial_number,"OCSP target serial mismatch")
    need(single.hash_algorithm.name in ('sha1','sha256','sha384','sha512'),"unsupported CertID digest")
    request=ocsp.OCSPRequestBuilder().add_certificate(leaf,issuer,single.hash_algorithm).build()
    need(single.issuer_name_hash==request.issuer_name_hash and single.issuer_key_hash==request.issuer_key_hash,"OCSP issuer binding mismatch")
    need(single.this_update_utc<=now and single.next_update_utc is not None and now<single.next_update_utc,"OCSP stale, future or missing nextUpdate")
    need(r.produced_at_utc<=now and (now-r.produced_at_utc).total_seconds()<=age and (now-single.this_update_utc).total_seconds()<=age and single.this_update_utc<=r.produced_at_utc<single.next_update_utc,"OCSP evidence outside freshness bounds")
    actual_nonce=None
    for ext in r.extensions:
        need(isinstance(ext.value,x509.OCSPNonce),"unknown OCSP response extension unsupported")
        actual_nonce=ext.value.nonce
    expected_nonce=b64(d['nonce'],True,64) if 'nonce' in d else None
    if expected_nonce is not None:need(1<=len(expected_nonce)<=64,"invalid expected nonce")
    need(actual_nonce==expected_nonce,"OCSP nonce mismatch or unexpected nonce")
    for ext in r.single_extensions:raise ReviewError("OCSP single response extensions unsupported")
    signer=certificate(d['responder_pem']) if 'responder_pem' in d else issuer
    if signer.fingerprint(hashes.SHA256())!=issuer.fingerprint(hashes.SHA256()):
        issuer_pair(signer,issuer,now)
        try:need(ExtendedKeyUsageOID.OCSP_SIGNING in signer.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value,"delegated responder lacks OCSP signing EKU")
        except x509.ExtensionNotFound:raise ReviewError("delegated responder EKU absent") from None
    try:need(signer.extensions.get_extension_for_class(x509.KeyUsage).value.digital_signature,"responder not permitted to sign")
    except x509.ExtensionNotFound:raise ReviewError("responder key usage absent") from None
    if r.responder_name is not None:need(r.responder_name==signer.subject,"OCSP responder name mismatch")
    else:need(r.responder_key_hash==x509.SubjectKeyIdentifier.from_public_key(signer.public_key()).digest,"OCSP responder key hash mismatch")
    for cert in (issuer,leaf,signer):
        for ext in cert.extensions:
            if ext.critical:need(isinstance(ext.value,(x509.BasicConstraints,x509.KeyUsage,x509.ExtendedKeyUsage,x509.SubjectAlternativeName)),"unknown critical certificate extension")
    verify_x509(signer.public_key(),r.signature,r.tbs_response_bytes,r.signature_hash_algorithm,r.signature_algorithm_oid)
    status=single.certificate_status
    need(status!=ocsp.OCSPCertStatus.UNKNOWN,"OCSP status unknown")
    if status==ocsp.OCSPCertStatus.REVOKED:need(single.revocation_time_utc is not None and single.revocation_time_utc<=now,"invalid or future OCSP revocation time")
    return {**report(verified=True,certificate_status=status.name.lower(),issuer_sha256=issuer.fingerprint(hashes.SHA256()).hex(),responder_sha256=signer.fingerprint(hashes.SHA256()).hex(),target_sha256=leaf.fingerprint(hashes.SHA256()).hex(),full_root_chain_verified=False,delegated_responder=signer.fingerprint(hashes.SHA256())!=issuer.fingerprint(hashes.SHA256()),delegated_responder_revocation_verified=False),'status':'PASS' if status==ocsp.OCSPCertStatus.GOOD else 'FAIL'}
