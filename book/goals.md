# Goals and Non-Goals

### Goals

* Full `sops` encrypted file compatibility. Decrypt any `sops` supported format using `rops` and vice versa.
* Be consistent in how credentials are used, set and retrieved across integrations.
* Disincentivize unsecure operations.
* Support standard input (stdin) as an alternative to file paths whenever possible.
* Available as a rust library.

### Non-Goals

* Identical CLI to `sops` with full feature parity, see [preliminary non-goals](#preliminary-non-goals).

#### Preliminary Non-Goals

This list includes a collection of SOPS features which are currently not under consideration to be included in `rops`. Nothing here is set in stone, so feel free to open up an [issue](https://github.com/gibbz00/rops/issues) if there's anything you don't agree with 🙂

- The `--output` flag: Use `rops decrypt > FILE_NAME` instead?

- Partial retrieval: Use `rops decrypt FILE | jq` instead?

- Partial modification: 
  Use `rops edit` or `rops decrypt FILE | jq map | rops encrypt --format FORMAT` instead? This will unfortunately skip initialization vector reuse for unchanged value.

- The `--ignore-mac` flag: Deemed too insecure. `rops` files are instead encouraged to be placed under and then recovered with version control systems such as git.

- Manual key rotation (`--rotate/-r`): `rops` will automatically rotate the secret data key upon integration key id removal.

- Integrated formatting configuration: Might be better achieved by piping output through more powerful formatters.

- Integrated secrets publishing: This too might be better handled externally.

- `rops` as a remote key service: Possibly as a separate crate+binary conforming to [KMIP 2.1](https://en.wikipedia.org/wiki/Key_Management_Interoperability_Protocol) or higher.

- Access logging: Better handled by the respective integrations for now. Might become relevant to include in the remote key service.

### Currently missing features

- Sub-process secret passing. 
- Key groups.
- Storing file comments.
- Compute an additional MAC over active integration keys to prevent against manual removal without rotating the secret data key. (Currently not done by SOPS either.)
- Specify keys by `--key-file INTEGRATION PATH` flag.
- Show decrypted metadata with `--show-metadata/-s`. (Note that directly modifying the metadata will most likely break its integrity and prevent future decryption.)
