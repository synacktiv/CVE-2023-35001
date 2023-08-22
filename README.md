# nftables oob read/write exploit (CVE-2023-35001)

Exploit used at pwn2own Vancouver 2023 on Ubuntu desktop. The exploit supports
the kernel version available at the beginning of the event (5.19.0-35).

## Requirements

* C compiler
* Go compiler

## Usage

```
# Build
$ make

# Run
$ ./exploit
```

This produces a `lpe.zip` file which can be unpacked on the target. There are
two binaries in the archive:

- **wrapper**: A C binary used to enter namespaces
- **exploit**: The actual exploit

The `exploit` file is the program that should be executed. It uses the `wrapper`
program to call itself and enter a new namespace.
