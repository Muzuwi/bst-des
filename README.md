# BST - Implementation of DES
This repository contains an implementation of the DES encryption in Rust, using bitvec library.
Project for BST course, 2021, Łukasz K. 

# Building
- Download and install the [Rust environment](https://forge.rust-lang.org/infra/other-installation-methods.html#standalone-installers) for your platform. 
- Clone the repo
- Run `cargo build --release` to build the CLI interface
- Run `cargo test` to run the included implementation tests
- Run `cargo run --release -- <arguments>` to run the application

or

- Use the precompiled binary. This doesn't allow you to run the included tests, however

# Usage
The application takes the following arguments: 
- `-i <filename>` - specifies the input file to be encrypted/decrypted, 
- `-o <filename>` - specifies the output file
- `-k <filename>` - file to be used as a keystream for the algorithm
- `-e/-d` - encrypt (default) or decrypt the file

**Files that are not a multiple of 8 bytes will be padded with zeros - that includes both the input file and the key file**

Each 8-byte block of the input is processed using 8 bytes of the key file. **If the key file is smaller than the input file, keys will be reused, starting from the beginning**. You can test the effect of using a single key on the cipher text by simply creating a text file containing only 1 key.

Included in the repo is `random.bin` generated from the TRNG part of the course that can be used as a key file for the program. 
