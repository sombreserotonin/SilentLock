# SilentLock

**SilentLock** is a lightweight Rust-based file encryption and decryption tool designed for simplicity, speed, and secure transmission. It allows users to encrypt files and share them over the internet securely through a terminal interface, with a web interface in development.

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
git clone https://github.com/yourusername/SilentLock.git
cd SilentLock
cargo build --release
```

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
