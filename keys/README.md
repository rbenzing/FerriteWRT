# Release signing keys

`release.pub` is the ed25519 public key that verifies `SHA256SUMS.sig` on every
release (see `docs/VERSIONING.md`). The image build installs it as
`/usr/share/ferritewrt/release.pub`, and from v0.3.0 the router checks every upgrade
against it, so it refuses images that were not produced by the release workflow.

The private key is never stored in this repository. The pair was created once with:

```bash
owr release keygen > keys/release.pub        # prints OWR_RELEASE_KEY=<hex> to stderr
```

The printed seed lives in the secret `OWR_RELEASE_KEY` of the GitHub environment named
`Release` (repository settings, Environments; the publish job of `release.yml` runs in that
environment). Keep it a secret, never an environment variable: variables are printed in
logs. Store the seed in a password manager as well. Losing it means routers can no longer
upgrade themselves: a release signed with a new key is refused, so every router would have
to be reflashed by hand with an image that carries the new key.

Without `release.pub`, tagged releases fail at the signing step on purpose. Manual
(`workflow_dispatch`) runs build and verify with a throw-away key and publish nothing.
