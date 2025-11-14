# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Migrated ESLint configuration from v8 to v9+ with flat config format
  - Replaced `.eslintrc.js` with `eslint.config.js`
  - Updated TypeScript ESLint integration to use `typescript-eslint` v8
- Updated all scanner methods to explicitly return promises for better ESLint compatibility
- Refactored codebase to align with ESLint v9 best practices

### Added
- Package overrides for `rimraf` (^6.0.1) and `glob` (^11.0.3) to address memory leak vulnerabilities
- Improved type safety across scanner implementations

### Security
- Addressed npm audit warnings through dependency updates and overrides
- Resolved memory leak concerns in transitive dependencies

## [0.1.2] - 2025-10-11

### Added
- Local MCP server support for scanning

### Changed
- Updated package dependencies

## Previous Versions
See git history for changes in versions 0.1.1 and earlier.
