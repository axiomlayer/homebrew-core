# Inert upstream automation

These 30 files are preserved byte-for-byte from `Homebrew/homebrew-core` at commit
`3624cbcd6aef759de1531bd8f5ffd6905045cadc` so fork ancestry remains easy to
audit. The archive includes the complete inherited `.github/` tree: every
baseline workflow, its JavaScript helper, Dependabot, Actionlint and CodeQL
configuration, and the issue and pull-request templates.
Every entry has a SHA-256 in `axiomlayer/tap-integrity-policy.json`; the verifier
also compares its bytes directly with the immutable Git baseline. Their
`.disabled` suffix and location outside GitHub's discovery paths make them inert.

They must not be renamed or copied back to their source paths in the AxiomLayer
fork. Upstream's bump, bottle, publish, automerge, dependency update, dispatch,
triage, and mutation jobs are for `Homebrew/homebrew-core`; AxiomLayer neither
carries their publisher credentials nor redistributes their artifacts. Only the
digest-pinned `.github/workflows/axiomlayer-tap-integrity.yml` is active here.
