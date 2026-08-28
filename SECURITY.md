# Security policy

## Reporting a vulnerability

Report privately — please do not open a public issue.

- **Preferred:** a [private security advisory](https://github.com/attenu-io/attenu-guard-ts/security/advisories/new)
  on this repository.
- **Email:** security@attenu.io

Please include the version, a description of the issue, and the smallest
reproduction you can manage. We aim to acknowledge within three working days
and to keep you informed while a fix is prepared. We will credit you in the
advisory unless you would rather we did not.

## Supported versions

The most recent minor release receives security fixes.

## Scope

In scope: anything that lets a delegated agent hold permissions its parent did
not hold, lets a denied action through, or lets a tampered ledger or evidence
bundle verify as intact.

Out of scope, because they are documented properties rather than defects:

- `HS256TestSigner` is symmetric and is not for production. Anyone able to
  verify with it can also forge. Use `Ed25519Signer`.
- The in-process integrity seal catches bugs and casual mutation. Code running
  in the same process can read the chain secret; tamper-evidence for a third
  party comes from the signed evidence bundle.
- A tool invoked around the guard rather than through it is not guarded. This
  library authorizes calls; it does not sandbox them.
