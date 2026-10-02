# OcspStapleReview

Offline RFC 6960 single-response signature, issuer/serial binding, responder authorization, nonce and freshness verification with a pinned direct issuer.

This is an independently implemented, complete selected offline input profile. It is not an equivalent rewrite of the entire upstream platform. Cryptographic primitives use cryptography; no upstream application is called.

## Contract

Run `ocsp-staple-review request.json` or pipe JSON to `ocsp-staple-review -`. Every input is local and supplied by its authorized owner. Parsing is bounded; duplicate fields, unknown algorithms, unsupported semantics, and failed signatures fail closed. The CLI returns 0 for PASS, 1 for FAIL, and 2 for OPEN. PASS applies only to the declared profile; it is not a general safety or CVP eligibility finding. Output excludes private material and raw credential identifiers.

## Boundaries

- No network, OCSP request transmission or root-chain building; single BasicOCSPResponse with direct or explicitly supplied delegated responder only. Delegated responder revocation is not evaluated, so that result is explicit scoped evidence rather than PKIX path validation. Unknown critical certificate or any unsupported response extension is rejected.

CVP organizational eligibility, an actually blocked legitimate task, application review, and approval remain OPEN. A repository and passing tests do not establish eligibility.

## Complete input profile

Required public `issuer_pem`, independent `issuer_sha256`, target `certificate_pem`, standard base64 `response_der`, timezone-aware `now` and bounded `max_age_seconds` (1 through 604800) bind a single BasicOCSPResponse. Optional `nonce` is canonical base64url and must exactly match; omitted nonce requires absence. Optional explicit public `responder_pem` permits a responder signed directly by the pinned issuer with OCSP-signing EKU, valid time and digitalSignature KeyUsage. CertID serial/name/key hashes, responder name/key hash, actual signature, thisUpdate/nextUpdate/producedAt freshness and supported extensions are checked. GOOD is PASS; authenticated REVOKED is FAIL with complete verification; UNKNOWN fails incomplete. Embedded response certificates are not a trust source. Root path and delegated-responder revocation remain unverified and are reported explicitly.

All accepted Ed25519 public keys are canonical nonidentity points in the main subgroup, checked through libsodium. Ed25519 signature R points must also be canonical nonidentity main-subgroup points and S must be below the group order. Certificates and CRLs require exactly matching inner/outer AlgorithmIdentifiers; the strict profile permits only RSA PKCS#1 SHA-256/384/512 with NULL parameters, ECDSA SHA-256/384/512 with absent parameters, and Ed25519 with absent parameters. OCSP permits the same explicit algorithm encodings and key-family/hash binding.

Where the profile accepts public PEM inputs, they contain one SubjectPublicKeyInfo or certificate object respectively, with canonical base64, no duplicate object and no trailing content. UTF-8 string values and keys reject lone surrogates; JSON results are safely ASCII-escaped.

The saved `examples/valid.json` is synthetic and contains only public data. Time-dependent examples retain their recorded reference `now`; tests generate fresh synthetic objects in temporary directories without changing examples.

## Install and check

```sh
python -m pip install .
python -m unittest discover -s tests -v
ocsp-staple-review examples/valid.json
```

See [ORIGIN.md](ORIGIN.md), [VALIDATION.md](VALIDATION.md), [LICENSE](LICENSE) and [UPSTREAM_LICENSE](UPSTREAM_LICENSE) for scope, evidence and attribution.
