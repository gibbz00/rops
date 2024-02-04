# Goals and Non-Goals

### Goals

* Full `sops` encrypted file compatibility. Decrypt any `sops` supported format using `rops` and vice versa.
* Be consistent in how credentials are used, set and retrieved across integrations.
* Disincentivize unsecure operations.
* Support standard input (stdin) as an alternative to file paths whenever possible.
* Available as a rust library.

### Non-Goals

* Identical CLI to `sops` with full feature parity, see [feature non-goals](#preliminary-non-goals).

### Preliminary Non-Goals

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

#### Currently, Missing Features

- [ ] Specify keys by `--key-file INTEGRATION PATH` flag.
- [ ] Show metadata `--show-metadata/-s`. Note that directly modifying the metadata will most likely break its integrity and prevent future decryption.
- [ ] [Sub-process secret passing.](https://github.com/getsops/sops#218passing-secrets-to-other-processes)
- [ ] [Key groups.](https://github.com/getsops/sops#214key-groups)
- [ ] Storing file comments.
- [ ] Compute an additional MAC over active integration keys to prevent against manual removal without rotating the secret data key. (Currently not done in SOPS either.)
