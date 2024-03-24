<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

- Remove `manage` from default features.

[Unreleased]: https://github.com/trussed-dev/trussed-staging/compare/v0.2.0...HEAD

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
