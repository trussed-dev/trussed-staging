<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

[Unreleased]: https://github.com/trussed-dev/trussed-staging/compare/v0.3.2...HEAD

- Update extensions:
  - `trussed-chunked` v0.2.0
  - `trussed-hkdf` v0.3.0
  - `trussed-hpke` v0.2.0
  - `trussed-manage` v0.2.0
  - `trussed-wrap-key-to-file` v0.2.0
  - `trussed-fs-info` v0.2.0

## [0.3.2][] - 2024-10-18

[0.3.2]: https://github.com/trussed-dev/trussed-staging/compare/v0.3.1...v0.3.2

- Implement `HpkeExtension` ([#25](https://github.com/trussed-dev/trussed-staging/pull/25))

## [0.3.1][] - 2024-08-01

[0.3.1]: https://github.com/trussed-dev/trussed-staging/compare/v0.3.0...v0.3.1

- Implement `FsInfoExtension` ([#27](https://github.com/trussed-dev/trussed-staging/pull/27))

## [0.3.0][] - 2024-03-25

[0.3.0]: https://github.com/trussed-dev/trussed-staging/compare/v0.2.0...v0.3.0

- Remove `manage` from default features.
- Implement `HkdfExtension` (moved from [Nitrokey/trussed-hkdf-backend][])

[Nitrokey/trussed-hkdf-backend]: https://github.com/Nitrokey/trussed-hkdf-backend

## [0.2.0][] - 2024-03-15

[0.2.0]: https://github.com/trussed-dev/trussed-staging/compare/v0.1.0...v0.2.0

- Move extension definitions into separate crates (see the `extensions` directory, [#3][])
- Add `ManageExtension`: Factory reset the entire device or the state of a given client ([#11][])
- `ChunkedExtension`: Add `AppendFile` and `PartialReadFile` syscalls.
- Remove the `encrypted-chunked` feature and always enable encrypted syscalls
  for `ChunkedExtension` ([#20][])

[#3]: https://github.com/trussed-dev/trussed-staging/issues/3
[#11]: https://github.com/trussed-dev/trussed-staging/pull/11
[#20]: https://github.com/trussed-dev/trussed-staging/issues/20

## [0.1.0][] - 2023-04-26

Initial release with these extensions:
- `ChunkedExtension`: read or write an unencrypted or encrypted file that is larger than the default Trussed message size in chunks
- `WrapKeyToFileExtension`: wrap or unwrap a key to or from a file

[0.1.0]: https://github.com/trussed-dev/trussed-staging/releases/tag/v0.1.0
