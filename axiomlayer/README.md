# AxiomLayer Homebrew tap integration

This directory makes the exact Homebrew input selected by Margay auditable
without turning the AxiomLayer fork into another package publisher.

The policy proves three Git relationships separately:

1. The candidate policy commit and tree must occur in the advertised history of
   `Homebrew/homebrew-core` `main`; verification deepens as needed and has no
   fixed history-depth ceiling.
2. A pull-request merge checkout must have the current AxiomLayer `main` as its
   exact first parent. The candidate pin may be newer than that protected base,
   but only integration-lane changes may follow the authenticated candidate.
3. Current `axiomlayer/homebrew-core` `main` is verified independently. Before
   the first integration merge it must be an exact upstream commit; afterward
   its own checked policy pin, verifier, workflow, inert archive, and
   integration-only descendants are authenticated without consulting the
   candidate pin.

The other immutable inputs are:

1. `axiomlayer/homebrew-core` must remain a true GitHub fork of
   `Homebrew/homebrew-core`, and its preserved snapshot branch is bound to an
   exact commit and tree in official upstream `main` history.
2. The private Dotfiles and Margay consumer manifests are represented only by
   their commit, tree, blob, and SHA-256 anchors plus their non-secret package
   selections. CI never receives credentials for either repository.
3. The four selected cask definition files are read from the exact pinned
   `Homebrew/homebrew-cask` commit. Their definition bytes and Git blobs are
   checked; their application URLs are never followed.

`verify_tap_integrity.py` recursively audits the 19 selected formula roots and
their formula dependencies as source declarations. It rejects symlinked or
escaping Formula paths, missing formulae, `sha256 :no_check`, malformed source
hashes, source blocks whose integrity is borrowed from an unrelated resource, a
changed pin/tree, an unexpected active workflow, archive byte, mode, or digest
drift, credentials, write permissions, host installation, or artifact transfer.
SHA declarations count only when their direct argument is a concrete 64-hex
literal or an exact `arm`/`intel` literal map. The fork expands the dynamic
checksum indirection inherited by Bash, Go, and Readline into policy-bound
literal declarations; each normalization is anchored to its upstream blob and
to the normalized blob and SHA-256. The canary audits those reviewed normalized
bytes only while current upstream still has the exact anchored source blob, so
an upstream edit cannot inherit the exception.
The baseline verifier never invokes Homebrew or evaluates Formula or Cask Ruby.
Every file inherited below the baseline `.github/` tree—including issue and pull
request templates—is moved into the inert archive, manifest-covered, and checked
byte-for-byte against the pinned commit. This leaves no inherited GitHub behavior
outside the quarantine.

The scheduled canary additionally inspects `go`, `jq`, `ripgrep`, and `sqlite`
without loading Homebrew or evaluating upstream Ruby. Formula and Cask bytes are
parsed as syntax by Ruby's non-evaluating Ripper parser; heredocs, strings, and
comments cannot masquerade as DSL calls. A clean-checkout
fingerprint is captured before and after each current-upstream audit and must
remain identical. This is the enforceable reason metadata inspection cannot call
install, fetch, test, service, bottle, uninstall, or artifact hooks or mutate
Homebrew state: no Formula/Cask Ruby or Homebrew runtime is loaded at all.

The daily canary resolves current `Homebrew/homebrew-core` `main`, checks out
that exact SHA into a temporary directory, and runs the same formula audit on
Linux and macOS, on x86_64 and ARM64. It prints the candidate commit, tree, and
closure digest and has no path that updates the fork's pin.

The baseline job accepts only same-repository `main` pull-request merge refs or
the protected `main` workflow in exact lowercase `axiomlayer/homebrew-core`.
The current-upstream matrix runs only for scheduled or manual invocations of
that exact default-branch workflow. All jobs use a closed set of dated
GitHub-hosted images, prove `RUNNER_ENVIRONMENT=github-hosted` before checkout,
make public Git fetches with prompts and inherited system/global Git
configuration and environment-injected Git options disabled in fresh temporary
homes, bind each checkout to
`FETCH_HEAD`, and receive no token permission. No public-fork code can route to
a fleet runner. An unconditional, Action-free terminal job named `Required tap
integrity authority` is the only required status check. It fails unless the
baseline ran successfully and the canary either succeeded on scheduled/manual
main or was correctly skipped on same-repository pull requests and
protected-main pushes.
The workflow verifier rejects duplicate YAML keys, aliases, anchors, and merge
keys before applying its exact digest and semantic contracts. The policy also
pins the verifier's own bytes, so replacing the implementation without an
explicit policy review fails before any audit runs.

## Local verification

Run the public baseline from this repository:

```sh
python3 axiomlayer/verify_tap_integrity.py baseline --repo .
```

The two private consumer clones can be proved against the signed policy without
giving CI access to either repository:

```sh
python3 axiomlayer/verify_tap_integrity.py consumers \
  --dotfiles-root /path/to/dotfiles-at-policy-commit \
  --margay-root /path/to/margay-at-policy-commit
```

Updating any pin or selection is a reviewed policy change. A passing canary is
evidence for that review; it is never automatic promotion.

## Required protected-main ruleset

Repository deployment uses two explicit ruleset phases. This avoids making the
terminal check mandatory before GitHub has had any protected `main` run from
which to discover that check.

Phase one is a temporary bootstrap ruleset. Before landing this integration,
create an active organization or repository ruleset targeting `main` with no
bypass actors. It must block branch deletion and non-fast-forward updates and
require changes through a pull request with one approving review. It must have
an empty required-status-check list. Land this integration through that
same-repository pull request. GitHub will now report `main` as protected, so the
workflow's push route can prove the pinned baseline.

While phase one is still active, manually dispatch `AxiomLayer tap integrity`
from `main`. Require the complete four-surface canary and terminal
`Required tap integrity authority` job to pass. Do not add the terminal check
before this successful protected-main run exists.

Phase two replaces the bootstrap ruleset with the final ruleset. Preserve the
same target, no-bypass policy, deletion block, non-fast-forward block, pull
request requirement, and one approving review, then also:

- dismiss stale approvals when new commits are pushed and require all review
  conversations to be resolved;
- require the branch to be up to date before merging (strict status checks); and
- require the exact status check `Required tap integrity authority`.

The policy file encodes both phases exactly: phase one cannot name a required
status check, and phase two must name only the terminal check above. Push,
schedule, and manual workflow routes refuse to run unless GitHub reports `main`
as protected. The verifier does not create or alter repository settings. The
repository is not deployment-ready until an administrator has completed phase
two and read the active ruleset back from GitHub.
