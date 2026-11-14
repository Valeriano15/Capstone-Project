# References and reading list

These links were checked and were reachable on 19 Oct 2026. They are starting points, not a
complete peer-reviewed literature review. Verify version-specific details when you implement.

## Methodology and standards

| Reference | Use |
| --- | --- |
| [NIST SP 800-115, Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final) | Assessment planning, methodology, findings analysis, mitigation |
| [FIRST CVSS v4.0 user guide](https://www.first.org/cvss/v4.0/user-guide) | Severity semantics, vectors, and the difference from risk |
| [CVE Program](https://www.cve.org/) | Vulnerability identifiers and program context |
| [NVD vulnerability APIs](https://nvd.nist.gov/developers/vulnerabilities) | Vulnerability data integration, verify schema and limits |

## Metasploit and Nmap

| Reference | Use |
| --- | --- |
| [Metasploit Framework overview](https://docs.rapid7.com/metasploit/msf-overview/) | Framework scope and concepts |
| [Metasploit RPC API](https://docs.rapid7.com/metasploit/rpc-api/) | Programmatic integration, check Framework versus Pro features |
| [Metasploit check-method guidance](https://docs.metasploit.com/docs/development/developing-modules/guides/how-to-write-a-check-method.html) | Preserve result meaning and uncertainty |
| [Metasploitable 2 documentation](https://docs.rapid7.com/metasploit/metasploitable-2/) | Candidate controlled lab target, note it is x86 |
| [Nmap XML output format](https://nmap.org/book/output-formats-xml-output.html) | Structured discovery output |

## AI safety and web testing

| Reference | Use |
| --- | --- |
| [OWASP prompt injection, LLM01:2025](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) | Threat modeling for untrusted reporting inputs |
| [OWASP Web Security Testing Guide](https://owasp.org/projects/web-security-testing-guide) | Web-testing methodology if web cases enter scope |

## Implementation stack

| Reference | Use |
| --- | --- |
| [FastAPI documentation](https://fastapi.tiangolo.com/) | Backend implementation |
| [Streamlit documentation](https://docs.streamlit.io/) | Optional simpler interface |
| [pytest documentation](https://docs.pytest.org/en/stable/) | Automated application tests |
| [FastMCP documentation](https://gofastmcp.com/) | The tool-server framework used in the prototype |
| [Model Context Protocol](https://modelcontextprotocol.io/) | Background on the protocol the prototype builds on |

## Suggested research searches

These are search starting points, not claims that specific papers exist:

- LLM-assisted penetration testing report generation evaluation
- evidence-grounded vulnerability reporting language models
- human-in-the-loop security assessment automation
- vulnerability assessment false positive evaluation benchmark
- indirect prompt injection security tool output
- Metasploit automation reproducible evaluation

## How to record a source

Keep one row per independent work: a short ID, full bibliographic details with DOI or stable
URL, source type, what it studied and how, what its evidence actually covers, the supported
conclusion, its limitations, which design choice it informs, and where it will be cited. Do not
fabricate citations. Cite the original work, not any tool that summarized it. Follow the IEEE
style the report template requires.
