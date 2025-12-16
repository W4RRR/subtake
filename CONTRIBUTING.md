# Contributing to SubTake Flow

First off, thank you for considering contributing to SubTake Flow! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
  - [Reporting Bugs](#reporting-bugs)
  - [Suggesting Features](#suggesting-features)
  - [Adding Fingerprints](#adding-fingerprints)
  - [Pull Requests](#pull-requests)
- [Development Setup](#development-setup)
- [Style Guidelines](#style-guidelines)

## Code of Conduct

This project and everyone participating in it is governed by our commitment to a harassment-free experience for everyone. Please be respectful and constructive in all interactions.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates.

**When reporting a bug, include:**

1. **Clear title** describing the issue
2. **Steps to reproduce** the behavior
3. **Expected behavior** vs what actually happened
4. **Environment details:**
   - OS and version
   - Bash version (`bash --version`)
   - Tool versions (subfinder, subzy, etc.)
5. **Relevant log output** (sanitize sensitive data!)
6. **Sample domain** (if public/non-sensitive)

### Suggesting Features

Feature requests are welcome! Please:

1. Check if the feature already exists or is planned
2. Describe the feature clearly
3. Explain the use case and benefit
4. Consider backward compatibility

### Adding Fingerprints

This is one of the most valuable contributions! 

**To add a new fingerprint:**

1. Fork the repository
2. Edit `fingerprints.yaml`
3. Add your fingerprint following this format:

```yaml
- cname: "service-domain.com"
  provider: "Service Name"
  fingerprint: "Error message pattern|Alternative pattern"
  status: "vulnerable"  # or "edge_case" or "not_vulnerable"
  docs: "https://docs.example.com"
```

4. **Test your fingerprint** if possible
5. Reference your source (bug bounty report, research, etc.)
6. Submit a Pull Request

**Fingerprint Guidelines:**
- Use regex-safe patterns
- Include multiple pattern variations with `|`
- Verify the fingerprint is current (services change their error pages)
- Add documentation links when available

### Pull Requests

1. Fork and clone the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
6. Push and create a Pull Request

**PR Checklist:**
- [ ] Code follows project style guidelines
- [ ] Self-reviewed the changes
- [ ] Added comments for complex logic
- [ ] Updated documentation if needed
- [ ] No sensitive data included
- [ ] Tested on both Linux and macOS (if possible)

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/subtake-flow.git
cd subtake-flow

# Make script executable
chmod +x subtake.sh

# Install development tools
sudo apt install shellcheck  # Bash linter

# Run linter
shellcheck subtake.sh

# Test with debug mode
./subtake.sh --debug example.com
```

## Style Guidelines

### Bash Scripting

```bash
# Use meaningful variable names
local subdomain_count=0  # Good
local x=0                # Bad

# Quote variables to prevent word splitting
echo "$variable"         # Good
echo $variable           # Bad (unless intentional)

# Use [[ ]] for conditionals
if [[ "$var" == "value" ]]; then  # Good
if [ "$var" == "value" ]; then    # Acceptable but less robust

# Use lowercase for local variables, UPPERCASE for constants/exports
local my_variable="value"
readonly MY_CONSTANT="value"

# Add comments for non-obvious logic
# Calculate probability score based on multiple factors
# Higher scores indicate higher takeover likelihood
score=$((score + 30))

# Use functions for reusable code
my_function() {
    local arg1="$1"
    # function body
}
```

### Commit Messages

```
type(scope): short description

Longer description if needed.

Fixes #123
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Formatting changes
- `refactor`: Code restructuring
- `test`: Adding tests
- `chore`: Maintenance tasks

### YAML (Fingerprints)

```yaml
# Use consistent indentation (2 spaces)
- cname: "example.com"
  provider: "Example Provider"
  fingerprint: "Pattern here"
  
# Add comments for unclear fingerprints
# Note: This fingerprint was changed in Jan 2024
- cname: "changed-service.com"
  fingerprint: "New error message"
```

## Questions?

Feel free to open an issue with the `question` label or reach out to the maintainers.

---

Thank you for contributing! 🚀

