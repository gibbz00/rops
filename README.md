# ROPS - A SOPS implementation in pure rust.

[![ci_status](https://github.com/gibbz00/rops/actions/workflows/ci.yml/badge.svg)](https://github.com/gibbz00/rops/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/gibbz00/rops/graph/badge.svg?token=nOnGXghHYk)](https://codecov.io/gh/gibbz00/rops)

### Goals

* Full `sops` encrypted file compatibility. Decrypt any `sops` supported format using `rops` and vice versa.
* Be consistent in how credentials are used, set and retrieved across integrations.
* Disincentivize unsecure operations.
* Available as a rust library.

### Non-Goals

* Identical CLI to `sops` with full feature parity, see [feature non-goals](#preliminary-non-goals).

## Features:

### File:

- Formats:
  - [X] YAML
  - [X] JSON
  - [X] TOML ([Currently](https://github.com/getsops/sops/pull/812) exclusive to `rops`)
  - [ ] INI
  - [ ] ENV
  - [ ] BINARY

#### Partial Encryption

All keys are encrypted by default, unless one of `encrypted_suffix`, `encrypted_regex`, `unencrypted_suffix`, `unencrypted_regex` exists as a metadata setting.

| Variant                     | Encrypt by default | Matched value      |
| ---                         | ---                | ---                |
| `encrypted_{suffix,regex}`  | No                 | Is encrypted       |
| `unncrypted_{suffix,regex}` | Yes                | Escapes encryption |

Note that any matched key "locks" the triggered encryption config for all descendant key-value pairs.
I.e. if the metadata contains `encrypted_suffix: "_encrypted"`, then the values for `i` and `ii` become encrypted in the map below:

```yaml
foo: bar
nested_encrypted:
  a:
      i: xxx
  b:
      ii: xxx
```

##### Compute MAC for encrypted values only

Unauthenticated changes in a plaintext value will still cause subsequent decryption attempts to fail.
This is because all values are hashed into a message authentication code (MAC) before any encryption takes place.
MAC verification will also fail after any unauthenticated addition, removal or reordering of values, regardless if they have been encrypted or not.
The `mac_only_encrypted` metadata boolean can be enabled to allow for such unauthenticated modifications of plaintext key-value pairs, so long as the key paths for encrypted values remain the same.

### Integrations:

- [X] `age` - Asymmetric
- [X] `aws_kms` - Symmetric [^1]
- [ ] `pgp` - Awaiting status update for: [OpenPGP Crypto Refresh](https://datatracker.ietf.org/doc/draft-ietf-openpgp-crypto-refresh/)
- [ ] `gcp_kms`
- [ ] `azure_kv`
- [ ] `hashicorp_kv`

Asymmetric encryption schemes require only the key id (i.e. public key) for the first encryption whilst symmetric schemes require both key id and private key up front.

[^1]: AWS KMS effectively becomes a symmetric encryption scheme when it requires private credentials to a remote encryption service, even if that service uses asymmetric encryption internally.

#### Integration key id string:

| Integration  | Syntax                    | Example                                                                                |
| ---          | ---                       | ---                                                                                    |
| age          | <age_recipient>           | `age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569`                       |
| aws_kms      | `<profile>.<aws_key_arn>` | `default.arn:aws:kms:eu-north-1:822284028627:key/029dba6d-60de-4364-ac5c-cbdd284acd0a` |

#### Integration private key string:

| Integration  | Syntax                                                  | Example                                                                     |
| ---          | ---                                                     | ---                                                                         |
| age          | <age_secret_key>                                        | `AGE-SECRET-KEY-1CZG0RPQJNDZWZMRMJLNYSF6H00WK0ECYAVE83ALFC2KE53WJ2FRSNZ8GC` |
| aws_kms      | `<profile>.<aws_access_key_id>.<aws_secret_access_key>` | `default.AKIAXXXXXXXXXXXXXXL2.BRZXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXigu`     |

Private keys are retrieved by first checking the existence of their respective environment variables, and then by attempting to read their respective key files.

##### Supplying private keys by environment variables.

Syntax is `ROPS_<INTEGRATION>='key1,key2'` where keys follow the above syntax. For example:
```
export ROPS_AWS_KMS='default.AKIAXXXXXXXXXXXXXXL2.BRZXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXigu'
```

##### Supplying private key by default key files.

Private keys can also be read from files, these reside by default in `<local_config_dir>/rops/<integration>_keys`. Each containing a *new-line* separated list of private keys following their respective formats.

`<local_config_dir>` varies by platform and defaults to:

| Platform | Value                                 | Example                                    |
| ---      | ---                                   | ---                                        |
| Linux    | `$XDG_CONFIG_HOME` or `$HOME/.config` | `/home/alice/.config`                      |
| macOS    | `$HOME/Library/Application Support`   | `/Users/Alice/Library/Application Support` |
| Windows  | `{FOLDERID_LocalAppData}`             | `C:\Users\Alice\AppData\Local`             |

Linux users wishing to use Age could for example save a file in `$HOME/.config/rops/age_keys` containing:
```
AGE-SECRET-KEY-1VR0S4...KD8D
AGE-SECRET-KEY-1GQ6XJ...DZ5W
```
(As opposed to setting `$ROPS_AGE=AGE-SECRET-KEY-1VR0S4...KD8D,AGE-SECRET-KEY-1GQ6XJ...DZ5W`.)

###### Overriding default key file location.

Default key file location can be overridden by setting a `$ROPS_<INTEGRATION>_KEY_FILE=<path>` environment variable, say `$ROPS_AGE_KEY_FILE=/tmp/temp_age_keys`.

##### TODO: Supplying private keys by integration key files.

Many integrations already store their keys in a dedicated location. `rops` does not parse these files, but aims to so in the future:

| Integration  | Windows                          | MacOS                    | Linux                    | Fallback                      | Format                                                                                                                    |
| ---          | ---                              | ---                      | ---                      | ---                           | ---                                                                                                                       |
| age          | N/A                              | N/A                      | N/A                      | N/A                           | N/A
| aws_kms      | `%UserProfile%\.aws\credentials` | `$HOME/.aws/credentials` | `$HOME/.aws/credentials` | `AWS_SHARED_CREDENTIALS_FILE` | [Reference](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-format-profile) |

#### Integration sub-features

##### AWS KMS

- [ ] [Profiles](https://github.com/getsops/sops#27kms-aws-profiles)
- [ ] [Roles](https://github.com/getsops/sops#28assuming-roles-and-using-kms-in-various-aws-accounts)
- [ ] [Context](https://github.com/getsops/sops#29aws-kms-encryption-context)


## CLI

<!-- TODO: paste automatically generated --help, and for each subcommand -->

### Config

<!-- TODO: paste automacially generated reference config -->

#### Retrieval

<!-- TODO:
- Find by: recursive directory traversal.
  - [ ] Recursive directory traversal.
  - [ ] Specify with a `$ROPS_CONFIG` environment variable.
  - [ ] Specify with a `--config/-c` flag.
-->

#### Missing features

- [ ] Update keys with `update-keys` sub-command.
- [ ] Partial encryption
    - [ ] `partial_encryption.{un,}encrypted.{ match: {regex,suffix}, pattern: "<pattern>" }`.
  - [ ] MAC encrypted values only.
    - [ ] `partial_encryption.mac_only_encrypted: true`.

### Missing features

- [ ] Specify keys by `--key-file INTEGRATION PATH` flag.
- [ ] Show metadata `--show-metadata/-s`. Note that directly modifying the metadata will most likely break its integrity and prevent future decryption.

### Misc

- [ ] [Sub-process secret passing.](https://github.com/getsops/sops#218passing-secrets-to-other-processes)
- [ ] [Key groups.](https://github.com/getsops/sops#214key-groups)
- [ ] Storing file comments.

#### Additional `rops` exclusives
- [X] Encrypt, decrypt or edit using stdin.
- [ ] Compute an additional MAC over active integration keys to prevent against manual removal without rotating the secret data key.

### Preliminary non-goals

- [`--output`](https://github.com/getsops/sops#217saving-output-to-a-file): Use `rops decrypt > FILE_NAME`?

- [Partial retrieval](https://github.com/getsops/sops#45extract-a-sub-part-of-a-document-tree): Use `rops decrypt FILE | jq`?

- [Partial modification](https://github.com/getsops/sops#46set-a-sub-part-in-a-document-tree): 
  Use `rops edit` or `rops decrypt FILE | jq map | rops encrypt --format FORMAT`? The latter will unfortunately skip initialization vector reuse for unchanged value.

- SOPS operations deemed unsecure:
  - `--ignore-mac`
  - Manual key rotation (`--rotate/-r`). `rops` will automatically rotate the secret data key upon integration key removal.

- [Integrated formatting configuration](https://github.com/getsops/sops#32json-and-json_binary-indentation)

- [Integrated secrets publishing](https://github.com/getsops/sops#219using-the-publish-command)

- [Remote key service](https://github.com/getsops/sops#215key-service) Possibly as a separate crate+binary conforming to [KMIP 2.1](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol) or higher.

- [Access logging](https://github.com/getsops/sops#216auditing) Better handled by the respective integrations for now. Might become relevant if a `rops` key service is developed.
