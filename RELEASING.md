# Release Process

## Automated Version Bumping

The easiest way to release is using automated version bumping. Choose your method:

### Method 1: GitHub Actions (Recommended)

Trigger a release from GitHub UI or CLI:

**Via GitHub UI:**
1. Go to [Actions](https://github.com/pfrederiksen/aws-access-map/actions/workflows/bump-version.yml)
2. Click "Run workflow"
3. Select version bump: **patch** (0.1.0 → 0.1.1), **minor** (0.1.0 → 0.2.0), or **major** (0.1.0 → 1.0.0)
4. Click "Run workflow"

**Via GitHub CLI:**
```bash
# Patch release (bug fixes)
gh workflow run bump-version.yml -f bump_type=patch

# Minor release (new features)
gh workflow run bump-version.yml -f bump_type=minor

# Major release (breaking changes)
gh workflow run bump-version.yml -f bump_type=major
```

### Method 2: Local Script

Use the included release script:

```bash
# Interactive - prompts for version type
./scripts/release.sh

# Or specify version type directly
./scripts/release.sh patch   # 0.1.0 → 0.1.1
./scripts/release.sh minor   # 0.1.0 → 0.2.0
./scripts/release.sh major   # 0.1.0 → 1.0.0
```

The script will:
- Show current and new version
- Ask for confirmation
- Create and push the tag
- Trigger the automated release

### Method 3: Manual Tag Creation

If you prefer manual control:

```bash
# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0"

# Push tag to trigger release workflow
git push origin v0.2.0
```

## What Happens Next

Once the version tag is pushed (by any method above), GitHub Actions automatically:

1. Runs all tests
2. Builds binaries for all platforms (Linux, macOS, Windows)
3. Creates archives (.tar.gz, .zip)
4. Generates checksums
5. Creates a GitHub release with release notes
6. Uploads all assets

That's it! No manual building required.

## Monitor Release Progress

Watch the workflow progress:
```bash
# View workflow status
gh run list --workflow=release.yml

# Or visit GitHub
open https://github.com/pfrederiksen/aws-access-map/actions
```

## Edit Release Notes (Optional)

After the automated release is created, you can enhance the release notes:

```bash
gh release edit v0.2.0
```

## Semantic Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Major** (v1.0.0 → v2.0.0): Breaking changes
- **Minor** (v0.1.0 → v0.2.0): New features, backwards compatible
- **Patch** (v0.1.0 → v0.1.1): Bug fixes, backwards compatible

## Release Checklist

Before creating a release:

- [ ] All tests passing: `go test ./...`
- [ ] Test coverage > 90%: `go test -coverprofile=coverage.out ./...`
- [ ] Lint passes: `golangci-lint run`
- [ ] Manual testing on real AWS account
- [ ] CHANGELOG.md updated (if maintaining separately)
- [ ] README.md updated with new features
- [ ] Version number bumped appropriately

## Commit Message Format

Use conventional commits for automatic changelog generation:

- `feat:` - New features (triggers minor version bump)
- `fix:` - Bug fixes (triggers patch version bump)
- `perf:` - Performance improvements
- `docs:` - Documentation changes
- `test:` - Test additions/changes
- `chore:` - Maintenance tasks
- `refactor:` - Code refactoring

Breaking changes:
```
feat!: redesign CLI interface

BREAKING CHANGE: The --output flag is now --format
```

## Rollback a Release

If you need to rollback:

```bash
# Delete the release
gh release delete v0.2.0

# Delete the tag locally
git tag -d v0.2.0

# Delete the tag remotely
git push --delete origin v0.2.0
```

## Pre-releases

For alpha/beta/rc versions:

```bash
# Create pre-release tag
git tag -a v0.2.0-rc.1 -m "Release candidate 1 for v0.2.0"
git push origin v0.2.0-rc.1

# GoReleaser will automatically mark it as pre-release
```

## Manual Release (Emergency)

If GitHub Actions is down:

```bash
# Install goreleaser
brew install goreleaser

# Create release locally
export GITHUB_TOKEN="your_token"
goreleaser release --clean

# Or just build without releasing
goreleaser build --snapshot --clean
```

## Testing the Release Workflow

Test without creating a release:

```bash
# Snapshot build (no git tag required)
goreleaser build --snapshot --clean --config .goreleaser.yml

# Check dist/ directory
ls -la dist/
```

## Troubleshooting

**Release workflow fails:**
1. Check GitHub Actions logs
2. Verify tag format matches `v*` pattern
3. Ensure GITHUB_TOKEN has correct permissions
4. Check goreleaser configuration: `goreleaser check`

**Binary size too large:**
- GoReleaser already uses `-s -w` ldflags
- Consider `upx` compression (add to goreleaser config)

**Missing platforms:**
- Add to `goos`/`goarch` in `.goreleaser.yml`
- Check for CGO dependencies (must be disabled for cross-compilation)
