# Introduction

`rops` aims to make the process of handling sensitive credentials a bit more refined than simply encrypting an entire config file. It does this by allowing the encryption of sensitive values only, whilst making sure that other parts can't be changed with malicious intent. One example use case is the remote hosting of version controlled rops-files with meaningful diff outputs. The [SOPS](https://github.com/getsops/sops) project, (which `rops` can be seen as Rust rewrite of), contains otherwise an excellent motivation section in its [README](https://github.com/getsops/sops/blob/main/README.rst) that explains all of this much better than I would.

The [goals](goals.md) chapter points out expected differences between these two projects, and the [concepts](concepts.md) chapter takes a deeper dive into how `rops` works. Those two chapters should serve both library and CLI users well. Remaining chapters primarily target the latter group. Library usage instructions are instead located at [docs.rs](https://docs.rs/rops).

`rops` the library, the CLI application, and its documentation is free and open source under the [Mozilla Public License
Version 2.0](https://www.mozilla.org/en-US/MPL/2.0/). The code can be found on [GitHub](https://github.com/gibbz00/rops) where issues and feature requests may also be [posted](https://github.com/gibbz00/rops/issues). Please follow the project's [Security Policy](https://github.com/gibbz00/rops/blob/main/SECURITY.md) if you encounter any vulnerability. All contributions are warmly welcomed, but make sure to read the [Contributing Guidelines](https://github.com/gibbz00/rops/blob/main/CONTRIBUTING.md) before opening a [pull request](https://github.com/gibbz00/rops/pulls). Feel free, however, to simply use the "Suggest an edit" button in the top right corner if you encounter any documentation errors along the way 😊

So without further ado, here's quick demo of `rops`' CLI.

<!-- TODO -->
