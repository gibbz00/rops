# CLI Configuration

A CLI config file can be used with so-called *creation rules*. These rules allow metadata settings to be provided "automatically", opposed repetitively including them as CLI flags.

Each creation rule has a *path regex* that file names are matched against. They're read in the order they appear, and the first match of any lookup cancels the next. (So there's no concept of creation rule merging.)

Stdin content can be matched with a creation rule that captures the pseudo file name of an empty string. The `.*` path regex can therefore be used as a general fallback for both input sources.

`rops` uses the following config file look up strategy:

1. `--config/-c <FILE>` flag.
2. File path set by the environment variable `$ROPS_CONFIG`.
3. File of the name `.rops.toml` found in the current working directory or any ancestor thereof.

```toml
{{#include assets/.rops.toml}}
```
