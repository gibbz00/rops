# Concepts

#### Partial Encryption

All keys are encrypted by default, unless one of `encrypted_suffix`, `encrypted_regex`, `unencrypted_suffix`, `unencrypted_regex` exists as a metadata setting.

| Variant                     | Encrypt by default | Matched value      |
| ---                         | ---                | ---                |
| `encrypted_{suffix,regex}`  | No                 | Is encrypted       |
| `unncrypted_{suffix,regex}` | Yes                | Escapes encryption |

Note that any matched key "locks" the triggered encryption config for all descendant key-value pairs.
I.e. if the metadata contains `encrypted_suffix: "_encrypted"`, then the values for `i` and `ii` become encrypted:

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
```sh
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
```sh
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
