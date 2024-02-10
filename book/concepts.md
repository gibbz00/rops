# Concepts

A *`rops` file* is first created by encrypting a plaintext *map* (collection of key-value pairs) of a specified file format. The resulting `rops` file will then contain the encrypted version of the map, followed by some `rops` file metadata.

Only the value part of any key-value pair is encrypted. This is done using an [authenticated encryption with additional data](https://en.wikipedia.org/wiki/Authenticated_encryption#Authenticated_encryption_with_associated_data) scheme. The secret key is a randomly generated 32 byte array called the *data key*, and the additional data is a concatenated path for key in question. Key paths as additional data is how unlawful key name changes and some forms of reorderings are protected against.

## Integrations

One or multiple *integrations* encrypt the data key in their own way once all values have been encrypted. The use of multiple integrations and *key pairs* within each integration add the necessary redundancy in case one integration private key is lost, or simply not present.

It is also how access to a `rops` file may be revoked without needing access to/knowledge of the file itself. To do so one would use an *identity and access management* (IAM) service in combination with a *key management service* (KMS) as the integration. If those services are used to encrypt and decrypt the data key, then access to the `rops` file may be revoked by removing the users' ability to access the KMS.

### Integration Key ID:

Integration key IDs used to encrypt the data key are all stored inside the `rops` file metadata section. The key IDs also serve as a way to identify which private key is to be used when things need to be decrypted it again. If the integration relies on an asymmetric encryption scheme, then only the integration key ID is needed when the `rops` file is being created, symmetric integration require on the other hand both key id and private key up front.

The key IDs conform to an integration specific syntax/format, and should not be any different as a function of where it is used.

| Integration  | Syntax                    | Example                                                                                |
| ---          | ---                       | ---                                                                                    |
| age          | <age_recipient>           | `age1se5ghfycr4n8kcwc3qwf234ymvmr2lex2a99wh8gpfx97glwt9hqch4569`                       |
| aws_kms      | `<profile>.<aws_key_arn>` | `default.arn:aws:kms:eu-north-1:822284028627:key/029dba6d-60de-4364-ac5c-cbdd284acd0a` |

### Private Integration Key:

Only one private integration key that can decrypt data key needs to be found for the data key to then decrypt the entire `rops` file map. [^1] Private keys are not stored in the metadata section, but instead retrieved by iterating over the stored integration key IDs. The strategy for where to look for a private key goes as follows:

1. In the environment variables.
2. In the `rops` key files.
3. (Future) In the default integration key files.


Private integration keys follow---just like the respective key IDs---a syntax/form that is unchanged regardless of context.

| Integration  | Syntax                                                  | Example                                                                     |
| ---          | ---                                                     | ---                                                                         |
| age          | <age_secret_key>                                        | `AGE-SECRET-KEY-1CZG0RPQJNDZWZMRMJLNYSF6H00WK0ECYAVE83ALFC2KE53WJ2FRSNZ8GC` |
| aws_kms      | `<profile>.<aws_access_key_id>.<aws_secret_access_key>` | `default.AKIAXXXXXXXXXXXXXXL2.BRZXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXigu`     |

[^1]: Unless the unimplemented key group future is.

##### To supply private keys by environment variables

Syntax is `ROPS_<INTEGRATION>='key1,key2'`. For example:
```sh
export ROPS_AWS_KMS='default.AKIAXXXXXXXXXXXXXXL2.BRZXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXigu'
```

##### To supply private keys by `rops` key files

Private keys can also be read from files, each containing a *new-line* separated list of private keys. They reside by default in `<local_config_dir>/rops/<integration>_keys`.

`<local_config_dir>` varies by platform and defaults to:

| Platform | Value                                 | Example                                    |
| ---      | ---                                   | ---                                        |
| Linux    | `$XDG_CONFIG_HOME` or `$HOME/.config` | `/home/alice/.config`                      |
| macOS    | `$HOME/Library/Application Support`   | `/Users/Alice/Library/Application Support` |
| Windows  | `{FOLDERID_LocalAppData}`             | `C:\Users\Alice\AppData\Local`             |

Linux users wishing to use the Age integration could for example save a file in `$HOME/.config/rops/age_keys` containing:

```sh
AGE-SECRET-KEY-1VR0S4...KD8D
AGE-SECRET-KEY-1GQ6XJ...DZ5W
```
(As opposed to setting `ROPS_AGE=AGE-SECRET-KEY-1VR0S4...KD8D,AGE-SECRET-KEY-1GQ6XJ...DZ5W`.)

The `rops` key file location can be overridden by setting a `ROPS_<INTEGRATION>_KEY_FILE=<path>` environment variable. `ROPS_AGE_KEY_FILE=/tmp/temp_age_keys` for instance.

##### To supply private keys using integration key files (Future)

Many integrations already store their keys in a dedicated location but in wildly different structures. `rops` does currently not parse these files, but it aims to so in the future:

| Integration  | Windows                          | MacOS                    | Linux                    | Fallback                      | Format                                                                                                                    |
| ---          | ---                              | ---                      | ---                      | ---                           | ---                                                                                                                       |
| age          | N/A                              | N/A                      | N/A                      | N/A                           | N/A
| aws_kms      | `%UserProfile%\.aws\credentials` | `$HOME/.aws/credentials` | `$HOME/.aws/credentials` | `AWS_SHARED_CREDENTIALS_FILE` | [Reference](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html#cli-configure-files-format-profile) |


#### Private key rotation

Compromised private keys can always be removed from a `rops` file. Such removals will automatically create a new data key used to re-encrypt all values. Other integration must be able to encrypt the new data key for storage when this happens. Or in other words; symmetric integration require the presence of their respective private keys during the removal of other private keys.

## Partial Encryption

All keys are encrypted by default, unless one of the `encrypted_suffix`, `encrypted_regex`, `unencrypted_suffix` or `unencrypted_regex` settings is present in the metadata:

| Variant                     | Encrypt by default | Matched value      |
| ---                         | ---                | ---                |
| `encrypted_{suffix,regex}`  | No                 | Is encrypted       |
| `unncrypted_{suffix,regex}` | Yes                | Escapes encryption |

Note that any matched key "locks" the triggered encryption config for all descendant key-value pairs.
If the metadata contains for instance `encrypted_suffix: "_encrypted"`, then the values for `i` and `ii` become encrypted as shown below:

```yaml
foo: bar
nested_encrypted:
  a:
      i: encrypted
  b:
      ii: encrypted
```

## Compute MAC for encrypted values only

Unauthenticated plaintext value changes in a partially encrypted `rops` files will still cause subsequent decryption attempts to fail. This is because all values are hashed into a *message authentication code* (MAC). The calculation happens before any encryption, and values are read in the other they appear. MAC verification at the decryption stage will, as such, deny any unauthenticated addition, removal or reordering of unique values. (Recall how concatenated key paths as additional encryption data prevents the other class of unauthenticated reordering; equal values but with different key names).

The `mac_only_encrypted` metadata setting can be enabled to lift this limitation, that is; enable the direct changes to plaintext values without causing MAC mismatch errors when attempting to decrypt the rest.
