<!--
Copyright (C) Nitrokey GmbH
SPDX-License-Identifier: CC0-1.0
-->

# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased][]

[Unreleased]: https://github.com/trussed-dev/trussed-staging/compare/hkdf-v0.2.0...HEAD

- Replace `trussed` dependency with `trussed-core`.

## [0.2.0][] - 2024-03-25

[0.2.0]: https://github.com/trussed-dev/trussed-staging/releases/tag/hkdf-v0.2.0

- Move the `trussed-hkdf` crate from the [Nitrokey/trussed-hkdf-backend][]
  repository into the [trussed-dev/trussed-staging][] repository
- Remove the `HkdfBackend`.  The `HkdfExtension` is now implemented by the
  `StagingBackend` in `trussed-staging` if the `hkdf` feature is enabled

[Nitrokey/trussed-hkdf-backend]: https://github.com/Nitrokey/trussed-hkdf-backend
[trussed-dev/trussed-staging]: https://github.com/trussed-dev/trussed-staging

## [0.1.0][] - 2024-02-20

[0.1.0]: https://github.com/Nitrokey/trussed-hkdf-backend/releases/tag/v0.1.0

Initial release of the `HkdfExtension` and its implementation in the `HkdfBackend`.
