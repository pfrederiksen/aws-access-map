#!/bin/bash

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}ℹ${NC} $1"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Function to get the latest git tag
get_latest_tag() {
    git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0"
}

# Function to parse version and bump it
bump_version() {
    local version=$1
    local bump_type=$2

    # Remove 'v' prefix
    version=${version#v}

    # Split into components
    IFS='.' read -r major minor patch <<< "$version"

    # Remove any pre-release or metadata suffixes
    patch=${patch%%-*}

    # Bump based on type
    case "$bump_type" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            print_error "Invalid bump type: $bump_type"
            exit 1
            ;;
    esac

    echo "v${major}.${minor}.${patch}"
}

# Main script
main() {
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository"
        exit 1
    fi

    # Check if working directory is clean
    if [[ -n $(git status -s) ]]; then
        print_warning "Working directory is not clean"
        git status -s
        echo
        read -p "Continue anyway? (y/N) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            print_info "Aborted"
            exit 1
        fi
    fi

    # Get bump type from argument or prompt
    if [[ -n "$1" ]]; then
        bump_type="$1"
    else
        echo
        echo "Select version bump type:"
        echo "  1) patch  (0.1.0 -> 0.1.1)"
        echo "  2) minor  (0.1.0 -> 0.2.0)"
        echo "  3) major  (0.1.0 -> 1.0.0)"
        echo
        read -p "Enter choice (1-3): " -n 1 -r choice
        echo

        case "$choice" in
            1) bump_type="patch" ;;
            2) bump_type="minor" ;;
            3) bump_type="major" ;;
            *)
                print_error "Invalid choice"
                exit 1
                ;;
        esac
    fi

    # Validate bump type
    if [[ ! "$bump_type" =~ ^(patch|minor|major)$ ]]; then
        print_error "Invalid bump type: $bump_type"
        echo "Usage: $0 [patch|minor|major]"
        exit 1
    fi

    # Get current version
    current_version=$(get_latest_tag)
    print_info "Current version: $current_version"

    # Calculate new version
    new_version=$(bump_version "$current_version" "$bump_type")
    print_info "New version: $new_version"

    echo
    read -p "Create and push tag $new_version? (y/N) " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Aborted"
        exit 1
    fi

    # Create annotated tag
    print_info "Creating tag..."
    git tag -a "$new_version" -m "Release $new_version"
    print_success "Created tag: $new_version"

    # Push tag to remote
    print_info "Pushing tag to remote..."
    git push origin "$new_version"
    print_success "Pushed tag to remote"

    echo
    print_success "Release $new_version initiated!"
    echo
    print_info "GitHub Actions will now:"
    echo "  • Run all tests"
    echo "  • Build binaries for all platforms"
    echo "  • Create GitHub release with assets"
    echo
    print_info "View progress at: https://github.com/$(git config --get remote.origin.url | sed 's/.*github.com[\/:]\(.*\)\.git/\1/')/actions"
}

main "$@"
