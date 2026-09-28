# Security Policy

## Reporting a Vulnerability

Please report security issues **privately**, not in a public issue:

1. Open the **Security** tab of this repository → **Report a vulnerability**
   (GitHub private vulnerability reporting) and fill in the advisory form.
2. If that option is unavailable, contact the maintainer
   [@Anismansuri03](https://github.com/Anismansuri03) on GitHub and ask for a
   private channel before sharing details.

Include in your report:

- What the issue is and what its impact would be
- Steps to reproduce (commands, configuration, OS version)
- Affected version or commit
- A suggested fix, if you have one

You will get an acknowledgment as soon as possible. Please allow reasonable
time for a fix before any public disclosure.

## Supported Versions

| Version | Supported           |
| ------- | ------------------- |
| 2.x     | ✅ (latest release) |
| < 2.0   | ❌                  |

## Scope

**In scope:** Inspector's own code in this repository — the Windows Service,
the report generator, `Inspector.ps1`, `Install-Inspector.bat`, the bundled
Sysmon config, and the CI/release workflow. Relevant examples: unsafe
rendering of captured data in the HTML report (e.g., injection through crafted
command lines), anything that could make Inspector leak data off the machine,
or integrity issues in the published release artifacts.

**Out of scope:** vulnerabilities in Sysmon, Windows, .NET, Spectre.Console,
or other third-party components; issues that require an already-compromised
machine or administrator access without demonstrating additional impact on
Inspector itself.
