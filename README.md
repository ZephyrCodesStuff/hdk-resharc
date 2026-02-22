<div align="center">

  <h1>hdk-resharc</h1>

  <p>
    <strong>A tiny utility to repack PlayStation Home SDAT archives from the legacy BAR format into the more modern SHARC format.</strong>
  </p>

  <p>
    <a href="https://github.com/ZephyrCodesStuff/hdk-resharc/actions"><img src="https://img.shields.io/github/actions/workflow/status/ZephyrCodesStuff/hdk-resharc/clippy.yml?branch=main&style=flat-square" alt="Build Status"></a>
    <a href="#license"><img src="https://img.shields.io/badge/license-AGPLv3-blue?style=flat-square" alt="License"></a>
  </p>

</div>

---

## 🌟 Authors

- [@zeph](https://github.com/ZephyrCodesStuff) (that's me!)

### Acknowledgements

- [@I-Knight-I](https://github.com/I-Knight-I) for their massive help with the cryptographic implementations, the compression algorithms and other miscellaneous bits of knowledge
- [@AgentDark447](https://github.com/GitHubProUser67) for their open-source software, allowing me to learn about the SHARC archive format
- @hykem for their efforts in reverse engineering the PS3 file formats such as NPD and SCE

## 📖 Overview

**hdk-resharc** is a small, focused utility built on top of [`hdk-rs`](https://github.com/ZephyrCodesStuff/hdk-rs). It takes PlayStation Home `.sdat` files whose inner archive is a legacy BAR (or already a SHARC) and repacks them into a normalised SDAT wrapping a fresh SHARC archive.

The typical use-case is modernising older PlayStation Home content packages so that they can be served by a revival server that expects SHARC-based SDATs.

### What it does, step by step

1. **Decrypts** the SDAT envelope.
2. **Detects** whether the inner archive is a BAR (v1) or a SHARC (v2).
3. **Extracts** every entry, preserving each file's hash identity and compression type.
4. **Skips** known-bad/placeholder file hashes that should not be forwarded.
5. **Repacks** the entries — sorted by name hash — into a brand-new, encrypted SHARC archive.
6. **Re-wraps** the SHARC in a fresh SDAT envelope.
7. Writes `<name>.normalized.sdat` and a companion `<name>.normalized.txt` containing the new SHARC timestamp (hex).

Both big-endian and little-endian source archives are supported; endianness is detected automatically and preserved in the output.

## 🚀 Usage

Pass one or more `.sdat` files as arguments. On Windows you can also drag-and-drop files directly onto the executable.

```sh
hdk-resharc <file1.sdat> [file2.sdat ...]
```

### Output

| File | Description |
| :--- | :---------- |
| `<name>.normalized.sdat` | The repacked SDAT containing the new SHARC archive |
| `<name>.normalized.txt`  | The new SHARC timestamp printed as a big-endian hex string |

## 💿 Building

```sh
# Clone the repository
git clone https://github.com/ZephyrCodesStuff/hdk-resharc
cd hdk-resharc

# Build a release binary
cargo build --release

# The binary will be at target/release/hdk-resharc
./target/release/hdk-resharc --help
```

## 📄 License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

**What this means:**

- ✅ **You can** use this tool to build open source workflows.
- ✅ **You can** modify the tool to suit your needs.
- 🛑 **If you distribute** a modified binary, you **must** provide the corresponding source code.

See [LICENSE](LICENSE) for more details.
