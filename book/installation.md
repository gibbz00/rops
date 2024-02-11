# Installation

### From crates.io

```sh
# (binary is still named rops)
cargo install rops-cli
```

#### If is binary not found in path

`cargo install` usually places binaries in its user level binary directory, default is usually being `$HOME/.cargo/bin` on Unix systems.
Make sure that it's in your `$PATH` by appending the following to your shell startup scripts, if applicable:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

Or for those that have manually set `$CARGO_HOME`:

```sh
# export CARGO_HOME="$XDG_DATA_HOME"/cargo
export PATH="$CARGO_HOME/bin:$PATH"
```
