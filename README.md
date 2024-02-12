# ROPS - A SOPS alternative in pure rust.

[![ci_status](https://img.shields.io/github/actions/workflow/status/gibbz00/rops/ci.yml?style=for-the-badge)](https://github.com/gibbz00/rops/actions/workflows/ci.yml)
[![codecov](https://img.shields.io/codecov/c/gh/gibbz00/rops?token=nOnGXghHYk&style=for-the-badge)](https://codecov.io/gh/gibbz00/rops)
[![license](https://img.shields.io/github/license/gibbz00/rops.svg?style=for-the-badge)](https://github.com/gibbz00/rops/blob/main/LICENSE)
[![crates_io](https://img.shields.io/crates/v/rops.svg?style=for-the-badge)](https://crates.io/crates/rops)
[![docs_rs](https://img.shields.io/docsrs/rops/latest.svg?style=for-the-badge)](https://docs.rs/rops)

SOPS: Secrets OPerationS is a secrets manager and editor for encrypted files of various configuration formats with support for AWS KMS, GCP KMS, Azure Key Vault, age, and PGP. It's also a CNCF sandbox project with more information available at [getsops.io](https://github.com/getsops/sops).

`rops` is an attempt at writing the SOPS in Rust, offering both a CLI and library crate. Currently supporting for YAML, JSON, TOML and integrations against Age and AWS KMS.

Check out the [`rops` book](https://gibbz00.github.io/rops/) for a demo and further information on how to get started.
