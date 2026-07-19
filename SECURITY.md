# ReCasaOS security policy

## Supported versions

ReCasaOS is a pre-1.0 continuation project. Security fixes are developed against
the latest `main` branch and, after ReCasaOS begins publishing releases, the
latest ReCasaOS release. Older snapshots, unmodified upstream CasaOS releases,
and arbitrary combinations of external CasaOS components are not supported
unless a specific advisory says otherwise.

Support is best effort and has no guaranteed response or remediation SLA. See
`RECASAOS_COMPONENTS.md` for the component boundary: a vulnerability in the UI,
Gateway, authentication service, Message Bus, installer, or another external
component may require a coordinated fix in its owning repository.

## Report a vulnerability privately

Use GitHub's **Security** tab and select **Report a vulnerability** to open a
private vulnerability report for this repository:

<https://github.com/EdmundFu-233/ReCasaOS/security/advisories/new>

If private vulnerability reporting is not available, open a public issue that
contains no exploit, secret, personal data, or sensitive deployment detail and
ask a maintainer to establish a private channel. Do not include vulnerability
details in that issue.

Please include, when safe:

- affected ReCasaOS commit/release and external component revisions;
- deployment topology and whether the issue is remotely reachable;
- impact, prerequisites, and minimal reproduction steps;
- logs or proof with tokens, credentials, hostnames, IPs, and personal data
  removed;
- any known workaround and your preferred disclosure timeline.

Maintainers will assess scope, coordinate across component repositories when
needed, prepare tests and a fix, and publish an advisory when appropriate.
Please avoid public disclosure until users have had a reasonable opportunity to
apply a released fix. This request does not restrict good-faith research or
independent disclosure obligations.

## Deployment security

The reverse-proxy examples expose only the opt-in, read-only `/public-files`
namespace and deny administrative routes. They are still not proof that a
particular host is public-ready. Before Internet exposure, follow
`docs/deployment/public-access.md` and close the applicable gates in
`docs/THREAT_MODEL.md`. Keep the full administrative surface on a private
management network.
