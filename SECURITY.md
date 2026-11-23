# Security policy

## Supported versions

`axt-protocol` is in development; no version has been released yet. Once versions are released,
only the latest one gets security fixes.

## Reporting a vulnerability

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/paxel/axt-rust/security/advisories/new)
(the repository's **Security** tab, **Report a vulnerability**). Do not open a public issue, pull
request or discussion for it.

Describe what an attacker gains: a message that the library accepts although its signature, its
sender or its addressee is wrong; a sealed message that someone other than its receiver can open;
a way to bring back, replace or delete another sender's record; input that crashes or hangs the
library, or makes it allocate without bound.

A flaw in the AXT specification itself is reported to [paxel/axt](https://github.com/paxel/axt/security/advisories/new).

The report and its fix are discussed in that advisory, which stays private until the fix is
published.

## What is already checked

The repository is held to the standard of [paxel/gates](https://github.com/paxel/gates): CodeQL,
OpenSSF Scorecard, SonarQube Cloud, the OSV gate on the locked dependencies, the alert gate,
clippy with a lint set that forbids panics and unsafe code, a coverage ratchet and weekly fuzzing.
Every change runs the conformance suite of the pinned AXT release, checked by its SHA-256 and its
attestation.

Every key, secret and certificate in the AXT test vectors is a test value of the AXT
specification (`spec/keys.md`, section 7.1) and is not a leak.
