# Release signing keys

`release.pub` is the ed25519 public key that verifies `SHA256SUMS.sig` on every
release (see `docs/VERSIONING.md`). It is compiled into the firmware so the router can
refuse images that were not produced by the release workflow.

The private key is never stored in this repository. Create a pair once:

```bash
owr release keygen > keys/release.pub        # prints OWR_RELEASE_KEY=<hex> to stderr
```

Put the printed seed into the GitHub Actions secret `OWR_RELEASE_KEY` (repository
settings, Secrets and variables, Actions) and commit `keys/release.pub`. Store the seed
in a password manager as well; losing it means every device must be re-keyed with a
release signed by the old key.

Until `release.pub` exists, tagged releases fail at the signing step on purpose.
Manual (`workflow_dispatch`) runs build and verify with a throw-away key and publish
nothing.
