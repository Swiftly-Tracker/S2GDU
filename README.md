# S2GDU

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Build Status](https://img.shields.io/github/actions/workflow/status/Swiftly-Tracker/S2GDU/build.yml?branch=main)](https://github.com/Swiftly-Tracker/S2GDU/actions)
[![Release](https://img.shields.io/github/v/release/Swiftly-Tracker/S2GDU?include_prereleases)](https://github.com/Swiftly-Tracker/S2GDU/releases)

Headless (idalib) CS2 gamedata tracker, built in C#.

Carries a set of gamedata signatures and vtable offsets from one CS2 build to the next. It runs over the pre-analysed `.i64` databases published by [CS2-IDA-Dumps](https://github.com/Swiftly-Tracker/CS2-IDA-Dumps), one IDA worker process per core. Each tracked function is described by anchors (strings, convars, vtables, calls, data pointers and more). A consensus matcher finds the function again in the new build. Then fresh signatures are generated for it. A function that can't be pinned down unambiguously is reported as `AMBIGUOUS` or `NONE`, never silently guessed.

## What it does

- **Dump fetching** - downloads a CS2-IDA-Dumps release's `.i64.7z` archives in parallel. It verifies each archive and each extracted database against the release's `provenance.json` SHA-256s and caches them under `cache/<tag>/`.
- **Seed import** - reads an existing SwiftlyS2 gamedata directory (`signatures.jsonc` + `offsets.jsonc`) and resolves every signature and vtable offset in the matching database. It crawls each resolved function into a `.gdu.pb` clue file.
- **Anchor crawling** - ten modules collect identity and reinforcement anchors per function: signature, string, convar, vtable, library, relational, data pointer, proximity, call chain and xref.
- **Backtracking** - finds every tracked function again in a newer build. It is two-pass: a parallel consensus vote over all anchors, then a rescue pass for the misses. The rescue pass uses calibrated data-pointer deltas and the functions already matched. Functions whose tracking signature still hits uniquely are kept as `SURVIVED` without rematching.
- **Signature regeneration** - builds the shortest unique signature for each match. It keeps mid-function signature offsets aligned through surrounding-instruction context. Prologue-skipping tracking signatures make the next survival check more robust.
- **VTable slot tracking** - re-derives each vtable entry's slot in the new build: direct slot, wrapper, or nearest size-compatible slot within tolerance.
- **Manual tracking** - `track` adds functions to a clue file by name or address. `gensig` prints a unique signature without tracking anything.
- **Gamedata export** - writes the tracked results back out as SwiftlyS2 `signatures.jsonc` and `offsets.jsonc`.

## Supported IDA versions

`--ida-sdk` selects which generated bindings to bind against: `auto` (default, detected from the installation), `9.2`, `9.3`, `9.4`.

## Install / Build

### Prerequisites

- [IDA Pro](https://hex-rays.com/ida-pro) 9.2, 9.3 or 9.4 with idalib, licensed for headless/library use (not needed for `fetch`, `export` and `list`)
- **.NET 10 SDK** (only to build from source; releases are self-contained)

### Prebuilt

Grab an archive for your platform from the [latest release](https://github.com/Swiftly-Tracker/S2GDU/releases/latest):

| Archive                                                                                                            | Platform |
| ------------------------------------------------------------------------------------------------------------------ | -------- |
| [`S2GDU-win-x64.zip`](https://github.com/Swiftly-Tracker/S2GDU/releases/latest/download/S2GDU-win-x64.zip)         | Windows  |
| [`S2GDU-linux-x64.zip`](https://github.com/Swiftly-Tracker/S2GDU/releases/latest/download/S2GDU-linux-x64.zip)     | Linux    |

Those links always resolve to the newest stable release. On Linux, `chmod +x S2GDU` after unzipping. Each archive is self-contained - no separate .NET runtime install needed.

### From source

```bash
git clone https://github.com/Swiftly-Tracker/S2GDU.git
cd S2GDU
dotnet build S2GDU.slnx -c Release
```

Output lands in `bin/Release/net10.0/`. To produce a standalone binary that relaunches itself as its own IDA worker (see [Architecture](#architecture)):

```bash
dotnet publish S2GDU.csproj -c Release \
  -r linux-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -o out/linux-x64
```

## Usage

```
s2gdu fetch     [--tag <tag|latest>] [--cache <dir>] [--repo <owner/name>] [regex]
s2gdu import    --input <dir> --seed <dir> --out <dir> [regex]
s2gdu backtrack --input <dir> --clues <dir> --out <dir> [regex]
s2gdu track     --input <db.i64> [--clue <file.gdu.pb>] [--out <file.gdu.pb>] <name|0xEA> ...
s2gdu gensig    --input <db.i64> <name|0xEA> ...
s2gdu export    --clues <dir|file> --out <dir> [--layout <dir>] [regex]
s2gdu list      --clues <dir|file> [regex]
```

| Command     | Description                                                                                                                                                                  |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `fetch`     | Download and verify a CS2-IDA-Dumps release into `<cache>/<tag>/`. Already cached databases are reused. Prints the resolved tag as its last stdout line: `tag=<tag>`.        |
| `import`    | Resolve a SwiftlyS2 seed gamedata directory in every database of `--input` and write `<binary>.gdu.pb` and `<binary>.report.json` into `--out`.                                             |
| `backtrack` | Match the clue files in `--clues` against the newer databases in `--input`, regenerate signatures and write the updated clue files and reports into `--out`.                |
| `track`     | Add functions (by name or `0x` address) to a database's clue file. Defaults to `<binary>.gdu.pb` next to the database.                                                     |
| `gensig`    | Print a unique signature for each function, tab-separated, without touching any clue file.                                                                                   |
| `export`    | Merge clue files into SwiftlyS2 gamedata (`signatures.jsonc` + `offsets.jsonc` in the `--out` directory). Conflicts are reported; first wins.                              |
| `list`      | Show every tracked function per clue file with its verdict, address, match method and exported signature or vtable slot.                                                    |

| Flag                       | Description                                                                                                                         |
| -------------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `--ida-path <dir>`         | Root of the IDA installation with idalib. Falls back to the `IDA_PATH` environment variable.                                         |
| `--ida-sdk <ver>`          | Generated bindings to bind against: `auto` (default), `9.2`, `9.3`, `9.4`.                                                          |
| `--cores <n>`              | Concurrent IDA worker processes, and concurrent downloads for `fetch`. Default: all logical processors.                             |
| `--input <path>`           | `import`/`backtrack`: directory of `.i64` databases (e.g. `cache/<tag>`). `track`/`gensig`: a single `.i64`.                         |
| `--seed <dir>`             | SwiftlyS2 gamedata directory holding `signatures.jsonc` and/or `offsets.jsonc` to import from.                                      |
| `--clues <dir\|file>`      | Directory of `.gdu.pb` clue files (or a single file for `export`/`list`).                                                            |
| `--clue <file.gdu.pb>`     | Clue file `track` adds to.                                                                                                           |
| `--out <path>`             | Output directory (`import`/`backtrack`/`export`) or clue file (`track`).                                                            |
| `--tag <tag\|latest>`      | `fetch` release tag. Default: `latest`.                                                                                              |
| `--cache <dir>`            | `fetch` cache root. Default: `cache`.                                                                                                |
| `--repo <owner/name>`      | `fetch` source repository. Default: `Swiftly-Tracker/CS2-IDA-Dumps`.                                                                 |
| `-h`, `--help`             | Show help.                                                                                                                          |

`[regex]` filters binaries by file name without extension, e.g. `"^(server\.dll|libserver\.so)$"`. Set `GITHUB_TOKEN` to raise the GitHub API rate limit for `fetch`.

Examples:

```bash
s2gdu fetch --tag v1.0.0 --cache cache
s2gdu import --input cache/v1.0.0 --seed path/to/gamedata/cs2/core --out clues/v1.0.0 --ida-path "C:\IDA" --cores 4
s2gdu fetch --cache cache
s2gdu backtrack --input cache/v1.1.0 --clues clues/v1.0.0 --out clues/v1.1.0 --ida-path "C:\IDA" "server"
s2gdu export --clues clues/v1.1.0 --out gamedata
```

## Architecture

```
S2GDU/
├── Program.cs                       # CLI entry point, flag parsing, batch orchestration, reporting
├── S2GDU.Ida/                       # Tracking engine, driven through generated P/Invoke bindings
│   ├── Index/                       # One IDA-thread pass building an immutable snapshot of the database
│   ├── Crawler/                     # Anchor modules (signature, string, convar, vtable, call chain, ...)
│   ├── Pathfinder/                  # Finders, validator and the two-pass consensus matcher
│   ├── Signatures/                  # Unique signature generation and search
│   ├── Rtti/                        # VTable symbol to class name normalization
│   ├── Jobs/                        # import / track / backtrack / gensig over a snapshot
│   ├── Gamedata/                    # SwiftlyS2 gamedata reader and writer
│   ├── Storage/                     # .gdu.pb clue file store
│   ├── Fetch/                       # CS2-IDA-Dumps release downloader and verifier
│   ├── Worker/                      # Worker pool + one-database-per-process IPC protocol
│   ├── Model/                       # Tracked function, anchor and match types
│   └── Generated/                   # Codegen output: bindings for each vendored IDA SDK version
├── S2GDU.Ida.Codegen/               # Header scanner that generates the bindings above from thirdparty/ida-sdk
├── S2GDU.Proto/                     # clue.proto, the .gdu.pb storage schema
├── S2GDU.Automation/                # Hosted job service driving the release pipeline (see below)
└── thirdparty/
    └── ida-sdk/                     # Vendored Hex-Rays IDA SDK headers, one directory per major.minor
```

Inside a worker, one pass on the IDA thread builds the snapshot. Anchor crawling, both matcher passes, signature regeneration and vtable slot updates then run in parallel over it.

CI (`.github/workflows/build.yml`) versions with GitVersion, builds the solution, runs the `S2GDU.Automation` tests, publishes self-contained `win-x64`/`linux-x64` builds, and tags/releases on push to `main`.

Each publish is a single self-contained binary; a worker relaunches that exact binary as its own subprocess (`--ida-worker`) rather than depending on a separate runtime install.

## Automation

`S2GDU.Automation` is a small hosted API that runs the end-to-end release pipeline on a dedicated Linux host. Given a [CS2-IDA-Dumps](https://github.com/Swiftly-Tracker/CS2-IDA-Dumps) tag, it does the following:

- fetches the databases
- backtracks the previous gamedata release's clue files inside a network-less IDA container
- exports SwiftlyS2 gamedata (`signatures.jsonc`, `offsets.jsonc`)
- publishes the clue archive and gamedata as a `gd-<tag>` GitHub release

`deploy/` holds the provisioning scripts used to stand up that host: IDA install, EULA acceptance, Docker image and systemd unit.

## Community

- **Issues**: [Report bugs and request features](https://github.com/Swiftly-Tracker/S2GDU/issues)
- **Security**: [Report privately](https://github.com/Swiftly-Tracker/S2GDU/security/advisories/new) - never in a public issue

## Acknowledgements

Thanks [K4ryuu](https://github.com/K4ryuu) for [IDA-GameDataTracker](https://github.com/K4ryuu/IDA-GameDataTracker), which the tracking engine is ported from.

All of the acknowledgements can be seen in [THIRDPARTY.md](THIRDPARTY.md)

## License

GPL-3.0. See [LICENSE](LICENSE).

---

<div align="center">
  <strong>Made with ❤️ by the Swiftly Development team</strong>
</div>
