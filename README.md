# ROPS - A SOPS implementation in pure rust.

[![ci_status](https://github.com/gibbz00/rops/actions/workflows/ci.yml/badge.svg)](https://github.com/gibbz00/rops/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/gibbz00/rops/graph/badge.svg?token=nOnGXghHYk)](https://codecov.io/gh/gibbz00/rops)

## Goals

* Full `sops` encrypted file compatibility. Decrypt any `sops` file using `rops` and vice versa.
* Available as a rust library.

## Non-Goals

* Identical CLI to `sops`.
* Full CLI feature parity with `sops`, see [feature non-goals](#preliminary-non-goals).

## Supported features:

### File:

- Formats:
  - [X] YAML
  - [ ] JSON
  - [ ] INI
  - [ ] ENV
  - [ ] BINARY
- [ ] Specify:
  - [ ] By flag: `--file-format`.
  - [ ] Infer by extension.
  - [X] In library.
- [ ] Partial encryption
    - [ ] CLI flag: `--{un,}encrypted-{suffix,regex} <pattern>`.
    - [ ] `.rops.yaml`: `partial_encryption.{un,}encrypted.{ match: {regex,suffix}, pattern: "<pattern>" }`.
    - [X] In library.
  - [ ] MAC encrypted values only.
    - [ ] Flag: `--mac-only-encrypted`.
    - [ ] `.rops.yaml`: `partial_encryption.mac_only_encrypted: true`.
- [ ] File comment encryption

#### Partial Encryption

All keys are encrypted by default, unless one of `encrypted_suffix`, `encrypted_regex`, `unencrypted_suffix`, `unencrypted_regex` exists as a metadata setting.

| Variant                     | Encrypt by default | Matched value      |
| ---                         | ---                | ---                |
| `encrypted_{suffix,regex}`  | No                 | Is encrypted       |
| `unncrypted_{suffix,regex}` | Yes                | Escapes encryption |

Note that any matched key "locks" the triggered encryption config for all descendant key-value pairs. I.e. if the metadata contains `encrypted_suffix: "_encrypted"`, then the values for `i` and `ii` become encrypted in the map below:

```yaml
foo: bar
nested_encrypted:
  a:
      i: xxx
  b:
      ii: xxx
```

##### Compute MAC for encrypted values only

Unauthenticated changes in a plaintext value will still cause subsequent decryption attempts to fail. This is because all values are hashed into a message authentication code (MAC) before any encryption takes place. MAC verification will also fail after any unauthenticated addition, removal or reordering of values, regardless if they have been encrypted or not. The `mac_only_encrypted` metadata boolean can be enabled to allow for such unauthenticated modifications of plaintext key-value pairs, so long as the key paths for encrypted values remain the same.

### Integrations:

- [X] `age`
- [ ] `pgp`
- [ ] `aws_kms`
- [ ] `gcp_kms`
- [ ] `azure_kv`
- [ ] `hashicorp_kv`

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
  - [ ] As an CLI argument.
  - [X] By an environment variable.
    - [X] Multiple keys per variable.
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

#### Default private key environment variables:

Integration  | Name              | Example                                                                                        |
---          | ---               | ---                                                                                            |
age          | ROPS_AGE          | `ROPS_AGE='AGE-SECRET-KEY-1CZG0RPQJNDZWZMRMJLNYSF6H00WK0ECYAVE83ALFC2KE53WJ2FRSNZ8GCL'`        |
pgp          | ROPS_PGP          | `ROPS_PGP='85D77543B3D624B63CEA9E6DBC17301B491B3F21,E60892BB9BD89A69F759A1A0A3D652173B763E8F'` |
aws_kms      | ROPS_AWS_KMS      | `ROPS_AWS_KMS='arn:aws:kms:us-east-1:656532927350:key/920aff2e-c5f1-4040-943a-047fa387b27e'`   |
gcp_kms      | ROPS_GCP_KMS      | `ROPS_GCP_KMS='projects/my-project/locations/global/keyRings/sops/cryptoKeys/sops-key'`        |
azure_kv     | ROPS_AZURE_KV     | `ROPS_AZURE_KV='https://sops.vault.azure.net/keys/sops-key/some-string'`                       |
hashicorp_kv | ROPS_HASHICORP_KV | `ROPS_HASHICORP_KV='http://127.0.0.1:8200/v1/sops/keys/firstkey'`                              |

All integrations also support providing multiple keys through a comma separated list, e.g. `ROPS_INTEGRATION='key1,key2'`.

#### Default key file locations

Integration  | Windows                       | MacOS                                                 | Linux                              | Format                     |
---          | ---                           | ---                                                   | ---                                | ---                        |
age          | `%AppData%\rops\age\keys.txt` | `$HOME/Library/Application Support/rops/age/keys.txt` | $XDG_CONFIG_HOME/rops/age/keys.txt | Per newline, `# Comments`. |
pgp          | `X`                           | `X`                                                   | `X`                                | `X`                        |
aws_kms      | `X`                           | `X`                                                   | `X`                                | `X`                        |
gcp_kms      | `X`                           | `X`                                                   | `X`                                | `X`                        |
azure_kv     | `X`                           | `X`                                                   | `X`                                | `X`                        |
hashicorp_kv | `X`                           | `X`                                                   | `X`                                | `X`                        |

### `.rops.yaml` configuration

- [ ] Regex based creation rules.
- [ ] Available keys per rule.

### CLI

- [ ] In place `$EDITOR` support (fallback to `vim`).
- [ ] Encrypt/Decrypt with `--in-place/-i`
- [ ] Encrypt/Decrypt with stdin.

### Misc

  - [ ] [Sub-process secret passing](https://github.com/getsops/sops#218passing-secrets-to-other-processes)

### Preliminary non-goals

- [`--output`](https://github.com/getsops/sops#217saving-output-to-a-file): Use `rops -d > FILE_NAME`?

- [Partial retrieval](https://github.com/getsops/sops#45extract-a-sub-part-of-a-document-tree): Use `rops -d FILE | jq`?

- [Partial modification](https://github.com/getsops/sops#46set-a-sub-part-in-a-document-tree): Use `rops -d FILE | jq map | rops -e --file-format FILE_FORMAT`?

  (Con: will skip initialization vector reuse for unchanged value.)

- `--ignore-mac` flag. Why?

- [Integrated formatting configuration](https://github.com/getsops/sops#32json-and-json_binary-indentation)

- [Integrated secrets publishing](https://github.com/getsops/sops#219using-the-publish-command)

- [Access logging](https://github.com/getsops/sops#216auditing) Better handled by the integrations?

- [Remote key service](https://github.com/getsops/sops#215key-service)
