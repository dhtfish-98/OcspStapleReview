# Origin and implementation scope

OcspStapleReview independently implements this selected scope: Offline RFC 6960 single-response signature, issuer/serial binding, responder authorization, nonce and freshness verification with a pinned direct issuer.

The research source is [digicert/pkilint](https://github.com/digicert/pkilint) at fixed commit `820a6146e255205b8b633de3e36856f011a628e3`. Source archive SHA-256: `0032bb47ccab1b72dc529944e581cfe4322d2b30e311d3a55b57b7133dd7ea62`. Its license is MIT; the exact source license notice is retained as `UPSTREAM_LICENSE`. The new application code and documentation are licensed under MIT (`LICENSE`). The upstream application is neither imported nor executed by the production package. No upstream application source is bundled in the production package.

## Selected source evidence

- [pkilint/pkix/ocsp/ocsp_validity.py](https://github.com/digicert/pkilint/blob/820a6146e255205b8b633de3e36856f011a628e3/pkilint/pkix/ocsp/ocsp_validity.py) — SHA-256 `c2d9172b3cbfedb33c14511af8dfd1b1f3b07c53a517adfb635a7084b2f82c27`.
- [pkilint/pkix/ocsp/ocsp_basic_response.py](https://github.com/digicert/pkilint/blob/820a6146e255205b8b633de3e36856f011a628e3/pkilint/pkix/ocsp/ocsp_basic_response.py) — SHA-256 `aacb870ac860fb90747691d47ea74c12343fe76c7de0e92415416e84c783e230`.
- [pkilint/pkix/ocsp/ocsp_response.py](https://github.com/digicert/pkilint/blob/820a6146e255205b8b633de3e36856f011a628e3/pkilint/pkix/ocsp/ocsp_response.py) — SHA-256 `32bb60e3dfbf0e5afe61c9619140c5c2737c9644a0264c2f2beaba170ae50c85`.

Full selected file contents and their inventory are retained in the research archive identified by `provenance/SOURCE_REVIEW.json`; those fixed links and hashes allow independent reconstruction. Review focused on BasicOCSPResponse structure/freshness source lint rules, new independent direct issuer, target and signature validation profile. This record does not assert a whole-platform source audit, original authorship of standards, or equivalence to all upstream behavior.

## Concrete new work

The new implementation owns bounded local input parsing, strict supported-field validation, the complete selected application logic, explicit trust input binding, fail-closed unsupported semantics, privacy-limited result fields, and a three-state CLI contract. Mature cryptographic primitives are reused rather than reimplemented. New scope and tests are substantive application work; a source SHA, rename, mirror or wrapper is not claimed as original contribution.

Required public `issuer_pem`, independent `issuer_sha256`, target `certificate_pem`, standard base64 `response_der`, timezone-aware `now` and bounded `max_age_seconds` (1 through 604800) bind a single BasicOCSPResponse. Optional `nonce` is canonical base64url and must exactly match; omitted nonce requires absence. Optional explicit public `responder_pem` permits a responder signed directly by the pinned issuer with OCSP-signing EKU, valid time and digitalSignature KeyUsage. CertID serial/name/key hashes, responder name/key hash, actual signature, thisUpdate/nextUpdate/producedAt freshness and supported extensions are checked. GOOD is PASS; authenticated REVOKED is FAIL with complete verification; UNKNOWN fails incomplete. Embedded response certificates are not a trust source. Root path and delegated-responder revocation remain unverified and are reported explicitly.

## Primitive policy

All Ed25519 keys and signature R points require canonical nonidentity main-subgroup points. The package calls libsodium point validation and also verifies [L-1]P+P equals identity with native scalar-multiplication/addition primitives, covering older system-library subgroup behavior. Certificate/CRL inner and outer AlgorithmIdentifiers must match exactly. The selected ASN.1 profile permits RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and absent-parameter Ed25519; family and digest must match the signer. These are deliberately strict declared limits.

Primary references: [libsodium point arithmetic](https://libsodium.gitbook.io/doc/advanced/point-arithmetic), [RFC 5280 certificate/CRL identifiers](https://www.rfc-editor.org/rfc/rfc5280.html#section-4.1.1.2), [RFC 8410 Ed25519 parameters](https://www.rfc-editor.org/rfc/rfc8410.html#section-3).

## Defensive use and application evidence

Inputs must belong to the authorized reviewer. Runtime performs no fetch, sample execution, private-key processing, key export, signing, remote modification or outbound communication. CVP organizational eligibility, evidence of a legitimate blocked task, application review and program acceptance remain OPEN. These local results alone do not establish them.
