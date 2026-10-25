# Security

agoranome-policy decides whether an agent pays for an offer, so a bug that lets
it admit an offer it should refuse is a security bug. So is anything that lets
someone forge or alter its signed receipts, or get the Claude Code hook to
approve a payment the policy refused.

## Reporting a problem

Email **hello@agoranome.com** with "Security" in the subject. Please include
the version (`agoranome-policy --version`), what you did, what happened and
what you expected. A policy file and the offer it was checked against help
most.

Please don't open a public issue for a problem that could cost someone money
until it's fixed. We'll reply to confirm we have your report and tell you what
we plan to do.

## Supported versions

Fixes go into the latest release on PyPI. The same wheel is served at
https://agoranome.com/policy.
