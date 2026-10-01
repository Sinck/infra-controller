# NICo mTLS and authorization

The admin CLI uses mTLS for administrative requests. Sites may retain their
Vault-issued client certificates or use an operator-managed admin PKI; neither
path requires JWT support in the CLI.

## Keep the two trust directions separate

- The CLI's `--root-ca-path` verifies **the API server**. Keep the site's server
  CA here; an independent admin CA does not replace it.
- The API's `[tls].root_cafile_path` and optional
  `[tls].admin_root_cafile_path` form its combined **client** trust store.
  Adding an admin CA does not replace the service or machine CA.
- TLS trust is not sufficient for admin access. The certificate must also pass
  Casbin authorization and the internal RBAC rules.

## Generating client certificates

Use the site's existing Vault issuance procedure or ask the operator's PKI
owner for a PEM client certificate chain and its matching unencrypted PEM
private key (PKCS#1, PKCS#8, or SEC1).
NICo does not require a particular external PKI product or issue these
operator credentials automatically.

For an independent admin PKI:

- Use a dedicated admin-client issuing intermediate whose entire issuance
  population is intended to have admin access. Its Subject CN must be globally
  unique across the API's combined trust store and encoded as an ASN.1
  `PrintableString`; the client leaf's Issuer CN must match it.
- The leaf must be valid for TLS client authentication, with the appropriate
  `clientAuth` extended key usage and signing key usage. Include any
  intermediates needed to build its chain to the configured trust anchor.
- Include the operator's identity in Subject CN, encoded as `PrintableString`.
  Some administrative operations require this identity, not just TLS trust.
  Optional Subject O/OU values supply organization/group audit information
  and must also use `PrintableString` to be parsed. Under the default internal
  RBAC rules, the group label does not restrict an admin's permissions.

Protect private keys at their source and on the CLI host. Only public CA
certificates belong in the API's trust ConfigMap; never install a CA private
key there.

## Configure API trust and authorization

For Helm deployments, follow the
[admin-client certificate configuration](https://github.com/dsx-ai-factory/infra-controller/blob/main/helm/PREREQUISITES.md#admin-client-certificates):

1. Set `nico-api.siteConfig.adminRootCertPem` to the public PEM trust bundle.
   Its default is empty; the optional bundle is materialized only when set,
   and requires `nico-api.siteConfig.enabled=true`.
2. Add the leaf's dedicated issuing-intermediate CN to
   `nico-api.auth.additionalIssuerCns`. The chart default is an empty list.
   Preserve every existing issuer CN that must continue to authenticate;
   replacing this list is not an additive update.
3. Apply those overrides through the site's Helm release workflow, preserving
   its other values. Changes to these chart values roll the API Deployment,
   loading both the trust bundle and issuer mapping.

The default `nico-api.auth.adminRootCafilePath` selects
`/etc/forge/carbide-api/site/admin_root_cert_pem`. The prerequisites document
also covers the alternate mounted path and the PEM-envelope validation rules.
Helm does not validate X.509 CA constraints, validity, or chain placement;
the PKI owner must validate those before installation.

The issuer mapping is `[auth.trust].additional_issuer_cns` in the API's TOML
configuration. It classifies certificates as `ExternalUser` by issuer CN
across the combined TLS trust store; it is **not** bound cryptographically to
the optional admin bundle. Do not list a shared or root CA CN for the new
admin issuer.

Every successfully verified client certificate is also a
`TrustedCertificate`. The default chart's Casbin `forge/*` rule accepts that
principal, but internal RBAC still requires an `ExternalUser` for the
`ForgeAdminCLI` access path. Keep `bypass_rbac=false` and
`nico-api.auth.permissiveMode=false` in production. Permissive mode bypasses
Casbin only, not internal RBAC.

The issuer-CN mapping takes precedence over custom `[auth.cli_certs]` criteria:
matching certificates skip that section's field restrictions and identity
extraction. If those criteria define the site's admin boundary, do not add
the issuer to `additionalIssuerCns` in step 2. Retain or configure the custom
criteria instead, and verify them with the site's Casbin and internal RBAC
policies. Use the issuer shortcut only when its dedicated issuance population
is intended to have admin access.

## Install and verify the CLI credential

Install the certificate chain and matching private key on the operator's CLI
host using the site's protected-file or Secret-mount procedure. Supply both
paths through the existing CLI inputs; no new authentication option is needed.
The [CLI connection guide](./nico-admin-cli.md#tls-options) documents flags,
environment variables, config-file keys, and fallback behavior.

Verify a protected, read-only operation:

```sh
nico-admin-cli \
  --api-url https://nico-api.example.com:1079 \
  --root-ca-path /etc/nico/certs/server-ca.crt \
  --client-cert-path /etc/nico/certs/admin-client.crt \
  --client-key-path /etc/nico/certs/admin-client.key \
  machine show
```

Replace the URL and paths with the site's values. Connection options precede
the subcommand. Leave `DISABLE_TLS_ENFORCEMENT` unset; setting it, even to an
empty value, disables server-certificate verification. With that override
unset, a successful query verifies server trust, client authentication, and
permission to read machines; an empty inventory is also a valid result.
`version` is only a connectivity check: it neither verifies the server
certificate nor sends a client certificate, and the API allows it anonymously.

Before relying on the new issuer, confirm that the existing Vault-issued
credential still works and that a certificate from an untrusted issuer is
rejected. A trusted certificate without an admin identity must not gain admin
access under the site's policy.

## Renewal, CA overlap, and recovery

The operator's PKI owns issuance and renewal. Before a leaf expires, obtain its
replacement, install the new chain/key together, and repeat the protected
query. If the files are lost or installation fails, repeat issuance and
installation; restore the site's configuration or trust bundle if that was
the cause. NICo does not automatically renew a CLI host's credential.

Changing the issuing CA is optional. Stage the new public trust anchor
alongside the old one and retain both issuer CN mappings, then apply the Helm
values. Verify old and new credentials, move operators to the new credentials,
and only then remove the retired admin anchor and mapping. Do not remove the
site's service/machine CA as part of an admin-only change. Verify the retired
credential is denied after the rollout; custom authorization mappings must
also stop granting it access.

## Revocation support boundary

This procedure preserves the existing CLI mTLS support level. The API listener
does not configure CRL or OCSP enforcement for client certificates; revoking a
leaf at the issuer alone does not cause the API to reject it. A leaf's
expiry or retiring its admin issuer's trust/authorization is the existing
containment mechanism, not a new per-certificate revocation feature.

For issuer retirement, remove its admin trust anchor and every mapping that
grants it admin access, apply the configuration, and verify rejection with the
old credential on a new connection. A trust-file refresh does not revalidate
already-established connections; completing the API rollout closes the old
connections. Issuer retirement affects all credentials from that issuer.
