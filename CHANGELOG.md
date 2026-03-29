# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Changed

- Align wire protocol commands with Python JoinMarket for compatibility

### Removed

- Remove connection and maker registration rate limits

## [0.1.0-alpha] - 2026-03-24

### Added

- Add arti variant to release build matrix
- Bundle libsqlite3-sys for cross-platform arti builds
- Add SQLite dev library installation for arti CI builds
- Bundle SQLite for arti builds to eliminate system dependency

### Changed

- Update dependencies and migrate xsalsa20poly1305 to crypto_secretbox

### Other

- initial commit
- Clarify PoW documentation for tordaemon vs arti backends

### Removed

- Remove unused dependencies and sync docs with codebase

### Reverted

- Revert "Bundle libsqlite3-sys for cross-platform arti builds"

