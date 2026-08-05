# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added `powerauth.service.rest.date.legacyFormatEnabled` property to restore the legacy `+00:00` timestamp offset on REST and callback responses for clients that cannot parse the Jackson 3 default `Z` designator [(#2436)](https://github.com/wultra/powerauth-server/issues/2436)

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
