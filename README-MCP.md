<p align="center">
    <img alt="Grype logo" src="https://user-images.githubusercontent.com/5199289/136855393-d0a9eef9-ccf1-4e2b-9d7c-7aad16a567e5.png" width="234">
</p>

# Grype MCP Server

An [MCP (Model Context Protocol)](https://modelcontextprotocol.io/) server that gives AI assistants the ability to scan container images, filesystems, and SBOMs for vulnerabilities using [grype](https://github.com/anchore/grype).

Vulnerability scanners produce long lists of CVEs. The hard part isn't finding them -- it's deciding which ones actually matter. By exposing grype as an MCP tool, your AI assistant can:

- **Scan** any image, directory, or SBOM on demand
- **Analyze** results in depth -- CVSS, EPSS, KEV status, fix availability
- **Reason** about reachability, attack surface, and real-world exploitability
- **Prioritize** what to fix first based on context, not just severity scores
- **Suggest fixes** with specific version upgrades or mitigation strategies

## Getting Started

### 1. Download the binary

Download the latest binary for your platform from the [Releases](https://github.com/romansok/grype-mcp/releases).

This binary is a **full grype CLI replacement** -- you can use it exactly like the standard `grype` command for all regular scanning, plus the additional `grype mcp` command to start the MCP server.

### 2. Configure your AI tool

#### Claude Code

Add to your Claude Code MCP settings (`~/.claude/settings.json` or project `.mcp.json`):

#### Cursor

Add to your Cursor MCP configuration (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "grype": {
      "command": "/path/to/grype",
      "args": ["mcp"]
    }
  }
}
```

Replace `/path/to/grype` with the actual path to the downloaded binary (e.g. `/usr/local/bin/grype` or `~/bin/grype`). If the binary is on your `PATH`, you can just use `"grype"`.

> **Note:** The first scan will take little longer than usual because grype needs to download its vulnerability database (~100 MB). Subsequent scans use the cached database and are much faster.

## Usage Examples

Once configured, just ask your AI assistant questions in natural language:

### Scan my project

> "Scan my project directory for vulnerabilities"

### Triage what matters

> "Scan `alpine:3.10.6` and tell me which vulnerabilities are actually exploitable based on EPSS scores and KEV status"

### Reachability analysis

> "Analyze my project's vulnerabilities -- for each critical CVE, check if the vulnerable package is actually used in my code and whether the affected function is reachable"

### Fix planning

> "Scan my project and give me a prioritized upgrade plan. Focus on vulnerabilities that have fixes available and the highest real-world risk"

### Scan a container image

> "Scan the `node:20-slim` image and compare its security posture against `node:20-alpine`"

### Export for CI/CD

> "Export the scan results for my project in SARIF format so I can upload them to GitHub Code Scanning"

## Tips

- Start with **scan** for a quick overview, then use **analyze** on specific findings that need deeper investigation
- Use `only_fixed` to focus on actionable vulnerabilities you can fix right now
- Ask the assistant to cross-reference findings with your actual code to assess reachability
- Combine with SBOM scanning (`sbom:` target) for offline or reproducible analysis


## MCP Tools

The server exposes three tools:

| Tool | Purpose | Output |
|------|---------|--------|
| **scan** | Quick vulnerability overview | Summary table with package names, versions, CVE IDs, severity, EPSS and risk scores |
| **analyze** | Deep vulnerability investigation | Full JSON with CVSS scores, EPSS, CWEs, KEV data, advisory URLs, fix versions, match details |
| **export** | Standard format export | SARIF (for CI/CD and IDEs) or CycloneDX (for SBOM exchange) |

### Common Parameters

All tools accept:

| Parameter | Required | Description |
|-----------|----------|-------------|
| `target` | Yes | Image ref (`alpine:latest`), directory (`dir:./`), SBOM (`sbom:bom.json`), PURL, or CPE |
| `fail_on_severity` | No | Flag when vulnerabilities meet or exceed: `negligible`, `low`, `medium`, `high`, `critical` |
| `only_fixed` | No | Only show vulnerabilities with a known fix |
| `only_not_fixed` | No | Only show vulnerabilities without a known fix |
| `by_cve` | No | Group results by CVE instead of vendor advisory IDs |
| `distro` | No | Override distro detection (e.g. `alpine-3.20`) |
| `platform` | No | Architecture for multi-arch images (e.g. `linux/arm64`) |

The **export** tool additionally requires `output_format`: `sarif`, `cyclonedx-json`, or `cyclonedx-xml`.

## Fork Architecture

This is a **lightweight fork** of [anchore/grype](https://github.com/anchore/grype). The only addition is the MCP server command (`grype mcp`). All upstream grype code is untouched, which means:

- Stays current with upstream grype releases via simple merges
- Full feature parity with the grype CLI
- The MCP server invokes grype as a subprocess -- no tight coupling to internal APIs


## Learn More

- [grype documentation](https://github.com/anchore/grype) -- full grype CLI reference

