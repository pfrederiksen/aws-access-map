# Release Process

## Automated Releases

Releases are automated using GitHub Actions and GoReleaser. When you push a version tag, the workflow automatically:

1. Runs all tests
2. Builds binaries for all platforms (Linux, macOS, Windows)
3. Creates archives (.tar.gz, .zip)
4. Generates checksums
5. Creates a GitHub release with release notes
6. Uploads all assets

## How to Release

### 1. Update Version in Code (if applicable)

If you have version constants in your code, update them:

```go
// cmd/aws-access-map/main.go
var version = "0.2.0"
```

### 2. Commit Changes

```bash
git add .
git commit -m "chore: prepare for v0.2.0 release"
git push
```

### 3. Create and Push Tag

```bash
# Create annotated tag
git tag -a v0.2.0 -m "Release v0.2.0"

# Push tag to trigger release workflow
git push origin v0.2.0
```

That's it! GitHub Actions will handle the rest.

### 4. Monitor Release

Watch the workflow progress:
```bash
# View workflow status
gh run list --workflow=release.yml

# Or visit GitHub
open https://github.com/pfrederiksen/aws-access-map/actions
```

### 5. Edit Release Notes (Optional)

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
