# Contributing to Inspector

Thanks for helping improve Inspector.

## Development setup

- Windows 10/11 with an **Administrator** PowerShell 5.1
- .NET 8 SDK (`dotnet --version`)
- Sysmon installed (required for capturing anything) — the repo ships a tuned
  config: `sysmon-config.xml`

```powershell
git clone https://github.com/Anismansuri03/Inspector.git
cd Inspector
.\Inspector.ps1 -Install     # builds service + report, registers the service
.\Inspector.ps1 -Activate    # start watching
.\Inspector.ps1 -Report      # console summary + HTML report
```

## Tests

```powershell
Invoke-Pester -Script .\tests\Inspector.Tests.ps1
```

- Run under **Windows PowerShell 5.1** with **Pester 3.4** (the in-box
  version). The suite is not compatible with Pester 5.x — CI pins 3.4.0.
- All tests must pass locally before you push; CI runs the same suite on every
  push and pull request.

## Guidelines

- **Local-only.** No telemetry, no network calls, no update checkers. Data must
  never leave the machine unless the user does it manually.
- **No unnecessary dependencies.** Prefer the BCL; propose new packages in an
  issue first.
- **Honest documentation.** If you change behavior, update `README.md` and/or
  `ARCHITECTURE.md`. Avoid absolute claims ("zero impact", "100% detection",
  "undetectable").
- **Match the existing style**: C# conventions used in the repo,
  PowerShell 5.1-compatible scripts (no PowerShell 7-only syntax).
- **Keep the test suite Pester 3.4-compatible** — do not migrate it to
  Pester 5.
- Never commit build output, personal paths, credentials, or generated files
  (`.gitignore` covers `bin/`, `obj/`, and reports).

## Pull requests

1. Create a feature branch from `main`.
2. Keep changes focused — one fix or feature per PR.
3. Run the build and tests locally (see above).
4. Open a PR describing *what* changed and *why*.

Bug reports and feature requests: [open an issue](https://github.com/Anismansuri03/Inspector/issues)
with reproduction steps, OS version, and relevant output.
