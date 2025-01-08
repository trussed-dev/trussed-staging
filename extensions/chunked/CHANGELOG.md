<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

[Unreleased]: https://github.com/trussed-dev/trussed-staging/compare/chunked-v0.2.0...HEAD

-

## [0.2.0][] - 2025-01-08

[0.2.0]: https://github.com/trussed-dev/trussed-staging/releases/tag/chunked-v0.2.0

- Replace `trussed` dependency with `trussed-core`.

## [0.1.0][] - 2024-03-15

- Extract the `ChunkedExtension` from `trussed-staging` 0.1.0 ([#3][])
- Add `AppendFile` and `PartialReadFile` syscalls
- Remove the `encrypted-chunked` feature and always enable encrypted syscalls ([#20][])

[#3]: https://github.com/trussed-dev/trussed-staging/issues/3
[#20]: https://github.com/trussed-dev/trussed-staging/issues/20

[0.1.0]: https://github.com/trussed-dev/trussed-staging/releases/tag/chunked-v0.1.0
