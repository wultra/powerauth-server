# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added an opt-in `includeDevicePublicKeys` request flag (default `false`) to the activation list, activation lookup, and v4 activation status read APIs. When enabled, the response `devicePublicKeys` map (key type name to normalized Base64) returns `ECDSA_P384` for protocol v4 `EC_P384` activations, `ECDSA_P384` and the ML-DSA key (`MLDSA_65`/`MLDSA_87`) for hybrid v4 activations (`EC_P384_ML_L3`/`EC_P384_ML_L5`), or the single `ECDSA_P256` key for protocol v3; it is empty for activations in the `CREATED` state. The `devicePublicKeys` map is omitted from the response by default, so existing callers are unaffected. A consumer of hybrid v4 keys must treat the keys as a single unit: both `ECDSA_P384` and exactly one ML-DSA key must be present and parseable, and both signatures must be verified over the same message; a missing ML-DSA key must not be treated as permission to downgrade to EC-only verification [(#2462)](https://github.com/wultra/powerauth-server/issues/2462)

### Fixed
- Restored numeric (epoch-millisecond) serialization of operation callback timestamps, which regressed to ISO-8601 strings after the Jackson 3 upgrade and broke callback consumers that parse the timestamps as numbers [(#2436)](https://github.com/wultra/powerauth-server/issues/2436)
- Fixed authenticator data deserialization when extensions are present, which could fail after the Jackson 3 upgrade [(#2444)](https://github.com/wultra/powerauth-server/issues/2444)

## [2.2.0] - 2026-07-20

### Added
- Temporary block of activation [(#2390)](https://github.com/wultra/powerauth-server/issues/2390)
- Added secure configuration store with per-application and per-activation scopes [(#2391)](https://github.com/wultra/powerauth-server/issues/2391)
- Added AAGUID for Wultra Authenticator 1.2 [(#2426)](https://github.com/wultra/powerauth-server/issues/2426)

### Changed
- Consolidated `CHANGELOG.md` to the strict Keep a Changelog 1.1.0 format and added Copilot changelog instructions [(#2398)](https://github.com/wultra/powerauth-server/issues/2398)
- Migrated to Spring Boot 4 and Jackson 3 [(#2379)](https://github.com/wultra/powerauth-server/issues/2379)
- Upgraded Docker base image to `ibm-semeru-runtimes:open-jdk-25.0.3.0-jre-noble` (OpenJDK 25) [(#2396)](https://github.com/wultra/powerauth-server/issues/2396)

[unreleased]: https://github.com/wultra/powerauth-server/compare/2.2.0...HEAD
[2.2.0]: https://github.com/wultra/powerauth-server/compare/2.1.0...2.2.0
