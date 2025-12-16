# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 2.x.x   | :white_check_mark: |
| 1.x.x   | :x:                |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in SubTake Flow, please report it responsibly.

### How to Report

**DO NOT** create a public GitHub issue for security vulnerabilities.

Instead, please:

1. **Email**: Send details to [security@example.com] (replace with your email)
2. **Encrypted**: Use PGP encryption if available
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 7 days
- **Resolution Timeline**: Depends on severity, typically 30-90 days
- **Credit**: We'll credit you in the release notes (unless you prefer anonymity)

### Scope

**In Scope:**
- Remote code execution vulnerabilities
- Command injection in the bash script
- Path traversal issues
- Sensitive data exposure in logs/output
- DNS rebinding or SSRF issues

**Out of Scope:**
- Issues requiring physical access
- Social engineering attacks
- Denial of Service (unless trivially exploitable)
- Issues in third-party tools (subfinder, subzy, etc.)

## Security Best Practices for Users

### Running the Tool Safely

```bash
# Run in isolated environment
docker run --rm -it subtake-flow example.com

# Use read-only file systems where possible
./subtake.sh -o /tmp/results example.com

# Avoid running as root
./subtake.sh example.com  # As regular user
```

### Protecting Your Data

1. **Review output directories** before sharing
2. **Sanitize logs** when reporting issues
3. **Use .gitignore** to prevent accidental commits
4. **Rotate API keys** if using authenticated services

### Network Security

- The tool makes DNS queries and HTTP requests
- These may be logged by your ISP or network admin
- Use a VPN or isolated network for sensitive targets
- Ensure you have authorization before scanning

## Responsible Disclosure

If you discover takeover vulnerabilities using this tool:

1. **Report to the affected organization first**
2. Follow their responsible disclosure policy
3. Give reasonable time for remediation
4. Do not exploit the vulnerability

## Acknowledgments

Thanks to all security researchers who help make this tool safer:

<!-- Add security contributors here -->

---

*This security policy is subject to change. Please check back periodically.*

