# Contributing to aws-access-map

Thanks for your interest in contributing! This project welcomes contributions from developers of all skill levels.

## Ways to Contribute

### 🐛 Report Bugs
Found a bug? Open an issue with:
- Clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- AWS setup details (if relevant, anonymized)
- Output of `./build/aws-access-map --version` (once we add it)

### 💡 Request Features
Have an idea? Open an issue describing:
- **Use case**: What problem are you trying to solve?
- **Current workaround**: How do you handle it today?
- **Proposed solution**: What would the command/API look like?
- **Example**: Show a concrete example of the feature in action

### 📝 Improve Documentation
- Fix typos or unclear sections
- Add more examples to README.md
- Document edge cases in CLAUDE.md
- Share real-world use cases

### 🔨 Submit Code

**Good first issues** are tagged in the issue tracker. Look for:
- Enhanced wildcard matching (Go glob libraries)
- Additional collectors (S3, KMS, SQS, SNS)
- Output formatting (JSON, CSV, table views)
- Test coverage improvements

## Development Setup

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/aws-access-map
cd aws-access-map

# 2. Build
make build

# 3. Test against your AWS account
./build/aws-access-map collect
./build/aws-access-map who-can "*" --action "*"

# 4. Run tests (when we add them)
make test
```

## Project Structure

```
aws-access-map/
├── cmd/aws-access-map/     # CLI entry point (cobra commands)
├── internal/
│   ├── collector/          # AWS API data fetchers
│   ├── graph/              # Permission graph (nodes + edges)
│   ├── query/              # Query engine (traversal algorithms)
│   └── policy/             # Policy parser (wildcards, conditions)
├── pkg/types/              # Shared data structures
└── testdata/               # Example policies, real AWS data
```

## Coding Guidelines

### Go Style
- Follow standard Go conventions (`gofmt`, `golint`)
- Keep functions small and focused
- Document exported functions and types
- Prefer explicit error handling over panics

### Testing
- Add tests for new features (especially policy parsing)
- Use `testdata/` for example policy documents
- Test against real AWS data when possible
- Mock AWS APIs for unit tests

### Git Workflow
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-thing`)
3. Make your changes with clear commit messages
4. Push to your fork
5. Open a Pull Request with:
   - Description of what changed and why
   - Reference to related issue (if applicable)
   - Example usage (if adding a feature)

## Example: Adding S3 Bucket Policy Support

**Goal**: Make `who-can` check S3 bucket policies, not just IAM policies.

```go
// 1. Add S3 collector (internal/collector/s3.go)
package collector

import "github.com/aws/aws-sdk-go-v2/service/s3"

func (c *Collector) collectS3Buckets(ctx context.Context) ([]*types.Resource, error) {
    // List buckets, get policies, parse into Resource structs
}

// 2. Update main collector
func (c *Collector) Collect(ctx context.Context) (*types.CollectionResult, error) {
    // ... existing code ...

    // Add S3 bucket collection
    buckets, err := c.collectS3Buckets(ctx)
    if err != nil {
        return nil, fmt.Errorf("failed to collect S3 buckets: %w", err)
    }
    result.Resources = append(result.Resources, buckets...)

    return result, nil
}

// 3. Update graph builder to process resource policies
// In internal/graph/graph.go
func (g *Graph) addResourcePolicyEdges(resource *Resource) error {
    // Parse resource policy and create edges
    // Resource policy grants access TO the resource FROM principals
}

// 4. Add test
func TestS3BucketPolicyParsing(t *testing.T) {
    policy := `{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::public-bucket/*"
        }]
    }`

    // Test that we correctly identify public access
}

// 5. Update README.md
// Mark S3 bucket policies as ✅ in "What it collects" section

// 6. Test with real AWS
aws s3api create-bucket --bucket test-access-map
aws s3api put-bucket-policy --bucket test-access-map --policy file://testdata/s3-policy.json
./build/aws-access-map collect
./build/aws-access-map who-can "arn:aws:s3:::test-access-map/*" --action s3:GetObject
```

## Architecture Guidance

See [CLAUDE.md](CLAUDE.md) for:
- Design decisions and rationale
- Common patterns
- Implementation priorities
- Testing strategies

## Questions?

- **General questions**: Open a discussion issue
- **Architecture questions**: See CLAUDE.md or open an issue
- **Bug reports**: Open an issue with reproducible steps
- **Feature requests**: Open an issue describing your use case

## Code of Conduct

Be respectful, constructive, and collaborative. We're all here to build better AWS tooling together.
