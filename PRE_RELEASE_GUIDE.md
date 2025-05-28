# Pre-Release v0.9 Creation Guide

This guide explains how to create the pre-release for Albator v0.9.

## Automated Release (Recommended)

The repository now includes a GitHub Actions workflow that will automatically create the pre-release when the `v0.9-pre` tag is pushed.

### Steps to create the pre-release:

1. **Create and push the pre-release tag:**
   ```bash
   git tag -a v0.9-pre -m "Pre-release version 0.9 - Enterprise-grade macOS security hardening framework"
   git push origin v0.9-pre
   ```

2. **The GitHub Actions workflow will automatically:**
   - Create a GitHub release named "🎉 Eureka - Albator v0.9 Pre-Release"
   - Mark it as a pre-release
   - Include the complete release notes from RELEASE_NOTES_v0.9.md

## Manual Release Creation

If you prefer to create the release manually through GitHub UI:

1. **Go to the repository releases page:**
   https://github.com/cluster2600/ALBATOR/releases

2. **Click "Create a new release"**

3. **Configure the release:**
   - **Tag version:** `v0.9-pre`
   - **Target:** main branch (commit 597fa25)
   - **Release title:** `🎉 Eureka - Albator v0.9 Pre-Release`
   - **Description:** Use the content from RELEASE_NOTES_v0.9.md
   - **Check:** "This is a pre-release"

## Release Content

The release notes are exactly as specified in the requirements:

```markdown
## [🎉 Eureka] Release 0.9 (28/05/2025)
- Comprehensive release of Albator version 0.9
- Milestone achievement of enterprise-grade macOS security hardening framework
- Complete implementation of Phase 3 and Phase 4 features
- Unified CLI and integration platform
- Advanced security, compliance, and threat detection capabilities
- Enterprise-level profile and fleet management
- Machine learning-powered security intelligence
```

## Target Commit

The pre-release should be based on commit `597fa25` which represents the latest main branch and includes all the Phase 3 and Phase 4 features mentioned in the CHANGELOG.md.

## Verification

After creation, verify that:
- [x] Release is marked as "Pre-release"
- [x] Release title matches: "🎉 Eureka - Albator v0.9 Pre-Release"  
- [x] Release notes match the specified content exactly
- [x] Tag `v0.9-pre` points to commit `597fa25`
- [x] Release is based on the main branch