# Node-auth: TPM-backed Bearer JWTs for Scout and DPU-agent

Scout and DPU-agent authenticate to the API with short-lived ES256 bearer
JWTs. Their signing keys are held by the host TPM or DPU fTPM, rather than in
the machine mTLS certificate files. This is separate from tenant
[SPIFFE JWT-SVID](spiffe-svid-sdd.md) issuance.

## Trust flow

```text
Scout / DPU-agent                                  nico-api
------------------                                 --------
create EK, temporary AK, and durable P-256 key
send EK certificate, AK data, and P-256 public ──► verify EK certificate
                                                    against configured TPM CA
                          ◄─────────────────────── MakeCredential challenge
ActivateCredential with EK + AK
TPM2_Certify(P-256 key, challenge) ─────────────► verify AK signature,
                                                    challenge, TPM key name,
                                                    and P-256 public area
                                                    store machine ID → public key

ES256 JWT {kid, aud, iat, exp} ──────────────────► look up kid, verify ES256,
                                                    derive SPIFFE machine ID
```

The API never trusts a public key merely because a node sent it. It records a
key only when all of the following hold:

- The EK certificate supplied during discovery chains to a configured TPM CA.
- The EK public area matches that certificate.
- The TPM activates an API-generated credential using the EK and temporary
  AK, proving the device has both objects.
- The AK's `TPM2_Certify` signature is valid and includes that credential as
  qualifying data.
- The certification name matches the key's marshalled `TPMT_PUBLIC`, whose
  P-256 point is the JWT verification key.

`kid` is the base64url SHA-256 digest of the uncompressed P-256 point. The
JWT has no `x5c` header and no caller-selected identity claim. The API maps a
registered `kid` to its enrolled machine ID and then constructs the machine
SPIFFE URI from `[auth.trust]`.

## Key lifetime and recovery

The node-auth signing key is an Owner-hierarchy P-256 primary object. Its
private half is derived inside the TPM from the hierarchy seed and fixed
template, so ordinary process restarts recreate the same non-exportable key.
`TPM2_Clear` changes the hierarchy seed, producing a new key; the next
discovery reenrolls it. The machine ID does not change: it continues to be
derived from discovery hardware, not TPM signing material.

Enrollment challenges are single-use. Once certified, the API caches the
registry locally and refreshes it from the database every 30 seconds so other
API replicas learn newly enrolled keys.

## Client behavior

`TpmNodeJwtMinter` signs five-minute ES256 tokens and re-mints when fewer
than 60 seconds remain. Scout accesses its host TPM through the configured
TPM path; DPU-agent uses `/dev/tpmrm0`, which reaches the DPU fTPM. The
agent's local `GetNodeToken` socket gives co-located services finished tokens
without giving them TPM access.

The regular mTLS channel can remain enabled while rolling this change, but it
is not a JWT trust anchor. Set `[node_auth].mtls_enabled = false` only after
the enrolled-token flow is operating fleet-wide.

## Configuration

The shipped configuration keeps node-auth disabled. Leave machine mTLS enabled
unless the site has an accepted EK certificate provisioning process and has
verified TPM-backed authentication across the fleet.

```toml
[node_auth]
enabled = false
mtls_enabled = true
max_token_ttl_sec = 900
```

If node-auth is enabled, the API requires `listen_mode = "tls"`, `[tls]`, and
`[auth.trust]`. It refuses bearer tokens on a plaintext listener. TPM EK
certificates must chain to a TPM CA configured in NICo before enrollment can
succeed.

## Out-of-band DPU fTPM EK enrollment

This is an operator-enrollment fallback for a BlueField DPU fTPM that has no
manufacturer-provisioned EK credential. It establishes operator trust rather
than manufacturer or hardware provenance. Use it only where that trust
boundary is acceptable; it cannot satisfy a requirement for a factory hardware
root of trust.

NVIDIA's [DOCA 3.2.2 fTPM over OP-TEE guide](https://networking-docs.nvidia.com/doca/archive/3-2-2/ftpm-over-op-tee)
describes enabling and validating the fTPM, but not an EK certificate,
endorsement credential, or factory enrollment flow. Earlier
[BlueField BSP documentation](https://docs.nvidia.com/networking/display/bluefieldbsp480/ftpm-over-op-tee.pdf)
labels fTPM beta and testing-only; that wording does not appear in the DOCA
3.2.2 guide. Separately, the [DOCA 3.2.3 known issues](https://networking-docs.nvidia.com/doca/archive/3-2-3/known-issues)
list fTPM TA development-key issue 4200690. The missing factory EK credential
is independent of that issue: a manufacturer-supported credential is needed
to establish hardware-origin identity without this operator enrollment.

### Ceremony roles and records

Keep the following roles separate:

- The asset custodian identifies the physical DPU through an independent
  inventory record and BMC identity.
- The enrollment operator accesses only that DPU through a controlled console
  or provisioning network.
- The CA operator holds the issuing CA private key in an HSM or other approved
  offline key store. The private key never goes to the DPU or NICo API.
- The NICo administrator registers only the issuing CA public certificate.

Record the DPU serial number, BMC identity, ceremony operator, time, EK public
key SHA-256 digest, leaf-certificate serial number, and CA key identifier. An
EK public key reported by an untrusted DPU OS alone is insufficient evidence
of physical-DPU identity.

### Procedure

1. Match the DPU to the expected inventory and BMC identity before opening an
   enrollment session. Enable OP-TEE in UEFI and reboot. Verify the OP-TEE,
   `tee`, and `tpm_ftpm_tee` paths and `/dev/tpmrm0` as NVIDIA documents.
2. In the controlled session, use the TPM 2.0 tools to create the standard RSA
   EK primary object and export only its public area. Do not export, create,
   or persist an EK private key outside the fTPM. Confirm that the public area
   is a 2048-bit RSA EK and record its digest with the asset record.
3. The CA operator verifies the ceremony record, creates a non-CA X.509 leaf
   certificate whose public key is exactly that EK public key, and signs it
   with the dedicated enrollment CA. Use a bounded validity period and an
   issuance serial number that can be audited and retired.
4. Before the DPU can discover with node-auth, register the CA *public*
   certificate in NICo with `nico-admin-cli tpm-ca add --filename <ca.der>`.
   Confirm `nico-admin-cli tpm-ca show` returns the expected subject and
   validity period.
5. Write the DER leaf certificate to the standard RSA EK certificate NV index
   `0x01c00002`. The provisioning implementation must set a read policy that
   works with the TPM client and make the index write-once or otherwise lock
   future writes after a byte-for-byte read-back check. Do not retain the CA
   private key on the DPU.
6. Read the leaf back from the fTPM, verify its chain to the configured CA,
   and compare its public key with a freshly read EK public area. Keep the
   resulting certificate fingerprint and ceremony record with the asset.
7. Run discovery. NICo verifies the certificate chain and public-key match,
   then uses `MakeCredential`, `ActivateCredential`, and `TPM2_Certify` to
   prove that the fTPM owns the EK, temporary AK, and durable JWT signing key.

### Recovery and security boundary

Repeat the ceremony after an fTPM clear, a board replacement, an EK mismatch,
or an asset-identity mismatch. Treat the enrollment CA as compromised if its
private key leaves the approved key store; remove its public certificate from
NICo and re-enroll the affected DPUs under a replacement CA.

This process proves only that the enrollment CA accepted the recorded DPU and
EK at ceremony time. It does not provide the factory-origin evidence supplied
by a manufacturer EK certificate chain. The fTPM protects non-exportable keys
from remote copying, but DPU OS root can use TPM operations and can cause a
local denial of service. The CA and the out-of-band asset check are therefore
the trust boundary for this workaround.
