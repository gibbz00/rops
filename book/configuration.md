# Configuration

<!-- TODO: paste automacially generated reference config -->

CLI config is retrieved from a...

1. `--config/-c <FILE>` flag.
2. File path set by the environment variable `$ROPS_CONFIG`.
3. File of the name `.rops.toml` found in the current working directory or any ancestor thereof.

First match of any lookup cancels the next, fallback being the default config shown above.
