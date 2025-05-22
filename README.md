# Cryptify

**Cryptify** is a lightweight Rust-based file encryption and decryption tool designed for simplicity, speed, and secure transmission. It allows users to encrypt files and share them over the internet securely through a terminal interface, with a web interface in development.

---

## Features

- Fast, minimal encryption and decryption
- Secure file handling using strong cryptographic algorithms
- Easy file uploads and downloads
- Designed for on-the-fly encryption and sharing

---

## Getting Started

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install)
- [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html)

### Installation

```bash
git clone https://github.com/yourusername/cryptify.git
cd cryptify
cargo build --release
```

### Usage

```bash
# Encrypt a file
./cryptify encrypt <input_file> <output_file>

# Decrypt a file
./cryptify decrypt <input_file> <output_file>
```

All terminal output is piped to a scratchfile:

```bash
cargo run -- encrypt file.txt file.txt.enc 2>&1 | tee cline/encrypt_output.txt
```

If output does not appear in the terminal (due to intermittent VSCode bugs), read directly from the scratchfile.

---

## Project Roadmap (Not in Order)

- [x] Core Web UI-based encryption/decryption
- [ ] Web UI overhaul with dark mode support
- [ ] Support for multiple encryption algorithms (e.g. AES, RSA, ChaCha20)
- [ ] Ability to send encrypted files to other users via Web UI
- [ ] Dockerization for easy deployment (including Unraid compatibility)
- [ ] Drag-and-drop support in Web UI
- [ ] Fix branding

---

## Contributing

Contributions are welcome. Please open an issue to discuss your proposed changes or ideas before submitting a pull request.

---

## License

This project is licensed under the MIT License.

---

## Credits

Built with Rust.
