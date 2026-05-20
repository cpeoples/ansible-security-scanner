# Output Formats

The scanner supports **10** output formats, selected with `--format <name>`.

| Format | `--format` value | File extension | Primary use case |
|--------|------------------|----------------|------------------|
| **Markdown** *(default)* | `markdown` | `.md` | Console output, MR/PR comments, wiki pages |
| **JSON** | `json` | `.json` | Programmatic processing, custom CI dashboards |
| **HTML** | `html` | `.html` | Stakeholder reports (dark/light mode) |
| **SARIF 2.1.0** | `sarif` | `.sarif` | GitHub Code Scanning, security aggregators |
| **GitLab SAST** | `gl-sast` / `gitlab-sast` | `.json` | GitLab Security Dashboard, MR security widget |
| **JUnit XML** | `junit` | `.xml` | GitLab/Jenkins `reports:junit` tab |
| **XML** (generic) | `xml` | `.xml` | Enterprise XML-based tools |
| **YAML** | `yaml` | `.yml` | YAML-driven config pipelines |
| **CSV** | `csv` | `.csv` | Spreadsheets, Excel, data analysis |
| **CycloneDX 1.5 SBOM** | `cyclonedx` / `sbom` | `.cdx.json` | Dependency-Track, GitHub Dependency Graph, Snyk |

The CycloneDX output is a full SBOM of the Ansible project: Galaxy collections,
roles, pip packages, bindep system packages, and execution-environment
container images - each mapped to a standard
[purl](https://github.com/package-url/purl-spec), alongside the scanner's
findings as CycloneDX `vulnerabilities[]` entries so downstream consumers get
both inventory and risk in a single document.

```bash
# --format is inferred from --output if omitted, so these two are equivalent:
ansible-security-scanner --output security_report.json
ansible-security-scanner --format json --output security_report.json
```

Explicit examples for every supported format:

```bash
# Default format - prints to console
ansible-security-scanner --format markdown
ansible-security-scanner --format json      --output security_report.json
ansible-security-scanner --format html      --output security_report.html
ansible-security-scanner --format sarif     --output results.sarif
ansible-security-scanner --format gl-sast   --output gl-sast-report.json
ansible-security-scanner --format junit     --output reports/security-results.xml
ansible-security-scanner --format csv       --output findings.csv
ansible-security-scanner --format cyclonedx --output sbom.cdx.json
```

Per-file reports (1:1 input:output, every scanned file gets a report):

```bash
ansible-security-scanner --directory ansible/ --output-per-file --format markdown
# Writes ./security-reports/site.yml.md, ./security-reports/roles/web/tasks/main.yml.md, etc.
```
