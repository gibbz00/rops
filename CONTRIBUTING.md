# Contributing to `rops`

There are some things that should be kept in mind when contributing to `rops`.
- Each commit is expected to pass CI on its own, (even if it's not automatically enforced by the CI pipeline).
- Bug fixes and feature additions should be accompanied by tests.
- Commit messages should at the very least give some explanation of what has changed, writing "Fix." does not count. Gold star to you if the message also includes a motivation.
- Each pull request should add their changes to the [CHANGELOG.md](CHANGELOG.md) and attempt to follow the conventions described in [Keep a Changelog](https://keepachangelog.com).

Structure requirements on commit messages, issues and pull requests are other than that pretty relaxed, (for now 🤞).

### Using pre-commit hooks

 Using a pre-commit hook to locally check simpler CI validation steps is encouraged to avoid commit squash requests by the maintainers, but also `git commit --amend && git push --force` abuse. This can be achieved by pasting the following into `.git/hooks/pre-commit`:

```sh
#!/bin/sh
set -e

# Make sure the toolchain is up to date and includes the
# necessary components specified in rust-toolchain.toml:
rustup update "$(rustup toolchain list | rg override | cut -d ' ' -f1)"

# Make sure things are properly formatted
cargo fmt -- --check
taplo fmt --check --diff

# Make sure things follow common linting recommendations
cargo clippy --all-features --tests -- -D warnings

# Check documentation
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --all-features --workspace --exclude rops-cli

# Some may also want to uncomment:
# cargo test --all-features
# mdbook test
# # https://github.com/crate-ci/typos
# typos
```

### Running tests

Pretty standard procedure apart from noting that some tests are behind feature flags, so:

```sh
cargo test --all-features
```

Book tests may also be done with:

```sh
mdbook test
```

### Building the book locally

Both [`mdbook`](https://rust-lang.github.io/mdBook/guide/installation.html) and the [`mdbook-cmdrun`](https://github.com/FauconFan/mdbook-cmdrun?tab=readme-ov-file#getting-started) processor will need to be installed before running `mdbook serve --open` or the like.

## Release (for maintainers)

1. Make sure CI is [not failing](https://github.com/gibbz00/rops/actions/workflows/ci.yml).
2. Bump version in the workspace `Cargo.toml` file.
3. Move the unreleased section in the CHANGELOG.md into a release with the current date added.
4. Finally:

```sh
git commit -am "Prepare X.X.X release."
git tag "X.X.X"
git push && git push --tags
```
