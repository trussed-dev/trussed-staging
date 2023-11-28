<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

- Add `ManageExtension`: Factory reset the entire device or the state of a given client ([#11][])
- `ChunkedExtension`: Add `AppendFile` and `PartialReadFile` syscalls.

[#11]: https://github.com/trussed-dev/trussed-staging/pull/11

[Unreleased]: https://github.com/Nitrokey/trussed-staging/compare/v0.1.0...HEAD

## [0.1.0][] - 2023-04-26

Initial release with these extensions:
- `ChunkedExtension`: read or write an unencrypted or encrypted file that is larger than the default Trussed message size in chunks
- `WrapKeyToFileExtension`: wrap or unwrap a key to or from a file

[0.1.0]: https://github.com/Nitrokey/trussed-staging/releases/tag/v0.1.0
