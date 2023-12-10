# ROPS - A SOPS implementation in pure rust.

[![ci_status](https://github.com/gibbz00/rops/actions/workflows/ci.yml/badge.svg)](https://github.com/gibbz00/rops/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/gibbz00/rops/graph/badge.svg?token=nOnGXghHYk)](https://codecov.io/gh/gibbz00/rops)

## Goals

* Full `sops` encrypted file compatibility. Decrypt any `sops` file using `rops` and vice versa.
* Also available as a high quality rust library.

## Non-Goals

* Identical CLI to `sops`.
* Full CLI feature parity with `sops`, see [feature non-goals](#preliminary-non-goals).

## Feature support:

### File:

- Formats:
  - [ ] JSON
  - [ ] YAML
  - [ ] INI
  - [ ] ENV
  - [ ] BINARY
- Choice:
  - [ ] Flag: `--file-format`.
  - [ ] Infer by extension.
- [Partial encryption](https://github.com/getsops/sops#48encrypting-only-parts-of-a-file)
  - [ ] Either escape encryption:
    - [ ] With a suffix.
      - [ ] Flag: `--unencrypted-suffix`.
      - [ ] `.rops.yaml`: `partial_encryption.escape.suffix`.
    - [ ] And/or through regex.
      - [ ] Flag: `--unencrypted-regex`.
      - [ ] `.rops.yaml`: `partial_encryption.escape.regex`.
  - [ ] Or limit encryption:
    - [ ] With a suffix
      - [ ] Flag: `--encrypted-suffix`.
      - [ ] `.rops.yaml`: `partial_encryption.limit.suffix`.
    - [ ] And/or through regex.
      - [ ] Flag: `--encrypted-regex`.
      - [ ] `.rops.yaml`: `partial_encryption.limit.regex`.
  - [ ] Message authentication code (MAC) for encrypted parts only.
    - Flag: `--mac-only-encrypted`.
    - `.rops.yaml`: `partial_encryption.mac_only_encrypted: true`.
- [ ] Last modified metadata
- [ ] File comment encryption

### Integrations:

- [ ] `age`
- [ ] `pgp`
- [ ] `aws_kms`
- [ ] `gcp_kms`
- [ ] `azure_kv`
- [ ] `hashicorp_kv`

#### Default key file locations

Integration  | Windows                       | MacOS                                                 | Linux                              | Format                     |
---          | ---                           | ---                                                   | ---                                | ---                        |
age          | `%AppData%\rops\age\keys.txt` | `$HOME/Library/Application Support/rops/age/keys.txt` | $XDG_CONFIG_HOME/rops/age/keys.txt | Per newline, `# Comments`. |
pgp          | `X`                           | `X`                                                   | `X`                                | `X`                        |
aws_kms      | `X`                           | `X`                                                   | `X`                                | `X`                        |
gcp_kms      | `X`                           | `X`                                                   | `X`                                | `X`                        |
azure_kv     | `X`                           | `X`                                                   | `X`                                | `X`                        |
hashicorp_kv | `X`                           | `X`                                                   | `X`                                | `X`                        |

#### Integration sub-features

##### AWS KMS

- [ ] [Profiles](https://github.com/getsops/sops#27kms-aws-profiles)
- [ ] [Roles](https://github.com/getsops/sops#28assuming-roles-and-using-kms-in-various-aws-accounts)
- [ ] [Context](https://github.com/getsops/sops#29aws-kms-encryption-context)

##### PGP

- [ ] [Alternative executable](https://github.com/getsops/sops#212specify-a-different-gpg-executable)
  - [ ] By flag.
  - [ ] By env.
  - [ ] By config.

### Key management

- Retrieval
  - [ ] By an enviroment variable.
    - [ ] Multiple keys per variable.
  - [ ] By key file location.
    - [ ] Specify with a `--key-file INTEGRATION PATH` flag.
    - [ ] Specify with a `$ROPS_INTEGRATION_KEY_FILE` environment variable.
    - [ ] Specified in the `.rops.yaml` config.
    - [ ] Built-in default location.
  - [ ] In the `.rops.yaml` config.
    - [ ] Specify with a `--config/-c` flag.
    - [ ] Specify with a `$ROPS_CONFIG` environment variable.
    - [ ] Recursive directory traversal.
    - [ ] Built-in default location.
- Changes
  - [ ] Rotate keys
    - [ ] Flag: `--rotate/-r`
  - [ ] Update keys
    - [ ] Read `.rops.yaml` with `update-keys` sub-command.
    - [ ] `--add INTEGRATION KEY FILE`
    - [ ] `--remove INTEGRATION KEY FILE`
    - [ ] `--show-master-keys/-s FILE`
- [ ] [Grouping](https://github.com/getsops/sops#214key-groups)

### `.rops.yaml` configuration

- [ ] Regex based creation rules.
- [ ] Available keys per rule.

### CLI

- [ ] In place `$EDITOR` support (fallback to `vim`).
- [ ] Encrypt/Decrypt with `--in-place/-i`
- [ ] Encrypt/Decrypt with stdin.

### Misc

- [ ] [Access logging](https://github.com/getsops/sops#216auditing)
- [ ] [Sub-process secret passing](https://github.com/getsops/sops#218passing-secrets-to-other-processes)

### Preliminary non-goals

- [`--output`](https://github.com/getsops/sops#217saving-output-to-a-file): Use `rops -d > FILE_NAME`?

- [Partial retrieval](https://github.com/getsops/sops#45extract-a-sub-part-of-a-document-tree): Use `rops -d FILE | jq`?

- [Partial modification](https://github.com/getsops/sops#46set-a-sub-part-in-a-document-tree): Use `rops -d FILE | jq map | rops -e --file-format FILE_FORMAT`?

- [Integrated formatting configuration](https://github.com/getsops/sops#32json-and-json_binary-indentation)

- [Integrated secrets publishing](https://github.com/getsops/sops#219using-the-publish-command)

- [Remote key service](https://github.com/getsops/sops#215key-service)
