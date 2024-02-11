#  Changelog

The format is based on the latest version of [Keep a Changelog](https://keepachangelog.com/en),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- CLI subcommand documentation for `rops keys {add,remove}`.

## [0.1.1] - 2024-02-11

### Added

- Additional status badges to REAME.md.
- Workspace crate point the `package.readme` to the repo README.md.
- Publish to crates.io release workflow job.

### Changed

- README.md badges now use "for-the-badge" styling.
- Release workflow is not triggered by creating git tags.

### Fixed

- Conditional compilation flags above `AgeConfig` visibility export.
