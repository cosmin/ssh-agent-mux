# `ssh-agent-mux` - Combine keys from multiple SSH agents into a single agent socket

> **Fork notice:** this is a maintained fork of [overhacked/ssh-agent-mux](https://github.com/overhacked/ssh-agent-mux). It adds SSH certificate support, `ssh-add` / `ssh-add -t` / `ssh-add -d` / `ssh-add -D` pass-through, and up-to-date dependencies. See the [CHANGELOG](CHANGELOG.md) for details.

Numerous types of SSH agents exist, such as the [1Password SSH agent](https://developer.1password.com/docs/ssh/agent/), which allows access to private keys in shared vaults, or [yubikey-agent](https://github.com/FiloSottile/yubikey-agent), allowing seamless access to private keys stored on [YubiKey](https://www.yubico.com/products/) cryptography devices. The `ssh` command allows using only one agent at-a-time, requiring you to configure per-server [`IdentityAgent`](https://www.mankier.com/5/ssh_config#IdentityAgent) settings or change the `SSH_AUTH_SOCK` environment variable depending on which agent you wish to use.

`ssh-agent-mux` combines multiple agents' keys into a single agent, allowing you to configure an SSH client just once. Provide all "upstream" SSH agents' `SSH_AUTH_SOCK` paths in the `ssh-agent-mux` [configuration](#configuration) and [run](#usage) `ssh-agent-mux` via your login scripts or OS's user service manager. Point your SSH configuration at `ssh-agent-mux`'s socket, and it will offer all available public keys from upstream agents as available for authentication.

## Features

* Simple TOML configuration syntax
* [systemd](https://systemd.io/) and [launchd](https://en.wikipedia.org/wiki/Launchd) user service manager integration
* [`session-bind@openssh.com` extension](https://github.com/openssh/openssh-portable/blob/46e52fdae08b89264a0b23f94391c2bf637def34/PROTOCOL.agent) pass-through support for agents that support key usage constraints
* OpenSSH certificates in upstream agents are listed and used for signing
* Adding keys (`ssh-add`, including `-t` lifetime and `-c` confirm constraints, and tools such as `step ssh login`) is forwarded to the first upstream agent that accepts the key. Agents that don't accept externally-added keys, such as [Secretive](https://github.com/maxgoedjen/secretive) and 1Password, are skipped, so list a general-purpose agent like OpenSSH's first.
* Removing keys (`ssh-add -d`) is routed to the upstream agent that holds the key; `ssh-add -D` is sent to every upstream agent

## Limitations

* **Destination-constrained keys** (`ssh-add -h`) are not supported. OpenSSH's agent enforces destination constraints using `session-bind` state on the same connection as the signing request, but `ssh-agent-mux` opens a new upstream connection per request. Adding such a key through the mux is refused. A destination-constrained key added *directly* to an upstream agent can still be used through the mux, but **without its destination restriction**, so avoid forwarding the mux socket (`ssh -A`) to hosts you don't trust with such keys.
* Certificates with no expiry (`valid_before` = forever) are not yet supported, pending the `ssh-key` 0.7 release.
* Locking the agent (`ssh-add -x`) and smartcard (PKCS#11) commands are not forwarded.

## Roadmap

* Background daemon support for running directly from the command line, like OpenSSH `ssh-agent`

Go ahead and [submit an issue](https://github.com/cosmin/ssh-agent-mux/issues/new) if there's something that would make `ssh-agent-mux` more useful to you or if it isn't working as it should!

## Installation

### Homebrew (macOS and Linux)

```console
$ brew install cosmin/tap/ssh-agent-mux
```

### From git

```console
$ cargo install --git https://github.com/cosmin/ssh-agent-mux
```

The minimum supported Rust version is `1.91.0`.

### Binary releases

Download binaries for various operating systems and architectures from the [releases page](https://github.com/cosmin/ssh-agent-mux/releases).

### Build from source

1. Clone the repository:
   ```console
   $ git clone https://github.com/cosmin/ssh-agent-mux.git && cd ssh-agent-mux/
   ```
2. Build:
   ```console
   $ cargo build --release
   ```

   The resulting binary is located at `target/release/ssh-agent-mux`
3. (Optional) Copy the binary to another location on your machine:
   ```console
   $ mkdir -p ~/bin && cp target/release/ssh-agent-mux ~/bin/
   ```

## Usage

### Linux (systemd)

```console
$ ssh-agent-mux --install-service

$ ssh-agent-mux --restart-service
OR
$ systemctl --user enable --now ssh-agent-mux.service
```

### macOS
```console
$ ssh-agent-mux --install-service
```

Service will automatically start as soon as it is installed.

## Configuration

`ssh-agent-mux` configuration is in [TOML](https://toml.io/en/v1.0.0) format. The default configuration file location is `~/.config/ssh-agent-mux/ssh-agent-mux.toml`. A simple configuration might look like:

```toml
agent_sock_paths = [
    "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
    "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
    "~/.ssh/yubikey-agent.sock",
]
```

The order of `agent_sock_paths` affects the order in which public keys are offered to an SSH server. If keys from multiple agents are listed on the server in your `authorized_keys` file, the agent listed first will be the one selected to authenticate with the server.

You can also specify all configuration on the command line, without using a configuration file at all. Any options specified on the command line override configuration file settings. To see the format of command line options, run:

```console
$ ssh-agent-mux --help
```

### Configuration file options

#### `agent_sock_paths` *[Array](https://toml.io/en/v1.0.0#array)*

Socket paths of upstream SSH agents to combine keys from. Must be specified as absolute paths. The order of `agent_sock_paths` affects the order in which public keys are offered to an SSH server. If keys from multiple agents are listed on the server in your `authorized_keys` file, the agent listed first will be the one selected to authenticate with the server.

Any of the paths can contain a shell-style reference to an environment variable, for example:

```toml
agent_sock_paths = [
    "${SSH_AUTH_SOCK}",
    "${SOME_DIRECTORY}/mystery-agent.sock",
    "~/.ssh/yubikey-agent.sock",
]
```

#### `listen_path` *[String](https://toml.io/en/v1.0.0#string)*

`ssh-agent-mux`'s own socket path. Your SSH client's agent socket (usually the `SSH_AUTH_SOCK` environment variable or the `IdentityAgent` configuration setting) must be set to this path.

*Default*: `~/.ssh/ssh-agent-mux.sock`

#### `log_level` *[String](https://toml.io/en/v1.0.0#string)*

Controls the verbosity of `ssh-agent-mux`'s output. Valid values are: `error`, `warn`, `info`, and `debug`. For development and debugging, the [`RUST_LOG` environment variable](https://docs.rs/env_logger/latest/env_logger/#enabling-logging) is also supported and overrides any `log_level` setting.

*Default*: `warn`

## Related projects

* [`ssh-manager`](https://github.com/omegion/ssh-manager): key manager for 1Password, Bitwarden, and AWS S3
* [`OmniSSHAgent`](https://github.com/masahide/OmniSSHAgent?tab=readme-ov-file): unifies multiple communication methods for SSH agents on Windows
* [`ssh-ident`](https://github.com/ccontavalli/ssh-ident): load ssh-agent identities on demand
* [`sshecret`](https://github.com/thcipriani/sshecret): "wrapper around ssh that automatically manages multiple `ssh-agent`s, each containing only a single ssh key"
* [`sshield`](https://github.com/gotlougit/sshield): drop-in ssh-agent replacement written in Rust using `russh`

## License

Dual-licensed under either [Apache License Version 2.0](https://opensource.org/license/apache-2-0) or [BSD 3-clause License](https://opensource.org/license/bsd-3-clause). You can choose between either one of them if you use this work.

`SPDX-License-Identifier: Apache-2.0 OR BSD-3-Clause`

## Copyright

Copyright &copy; 2024-2025, [Ross Williams](mailto:ross@ross-williams.net)
