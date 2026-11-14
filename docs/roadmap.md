# Build roadmap

This is a suggested working sequence, not the official course calendar. Map these onto the real
deadlines before treating any of it as a commitment.

## Immediate: fix the prototype so it runs

The code in `capstone/` does not import today. Its inner package is named `mcp`
(`capstone/mcp/src/mcp/`), which shadows the official `mcp` SDK that the server depends on
through FastMCP. The result is:

```
ModuleNotFoundError: No module named 'mcp.server'
```

Fix, in three edits:

1. In `capstone/mcp/pyproject.toml`, rename the project and the script, for example
   `name = "capstone_mcp"` and `mcp = "capstone_mcp:main"`.
2. Rename the folder `capstone/mcp/src/mcp/` to `capstone/mcp/src/capstone_mcp/`.
3. Re-sync the environment and confirm `import fastmcp` works and the server starts.

A missing `uvicorn` dependency also surfaced during testing. Resolve it after the rename, since
the name collision is the real blocker.

## Priority gates

- Gate 1: do not expand scope until the lab is reproducible.
- Gate 2: finish one non-AI end-to-end assessment before adding AI complexity.
- Gate 3: freeze features before formal evaluation.
- Gate 4: protect time for analysis, writing, and rehearsal.

## Suggested twelve-week sequence

| Week | Focus | Exit milestone |
| --- | --- | --- |
| 1 | Scope and research | Written scope and agreed research question |
| 2 | Lab feasibility | Reproducible positive and negative cases |
| 3 | Discovery | Scope guard, Nmap integration, XML parsing, job tracking |
| 4 | Evidence and matching | Traceable candidate findings with sources |
| 5 | Validation integration | Approved tests execute with retained evidence |
| 6 | Complete non-AI path | First end-to-end report |
| 7 | AI reporting | Reviewable AI-assisted report with fallback |
| 8 | Interface and integration | Another teammate can operate the system |
| 9 | Pilot and freeze | Repeatable formal protocol |
| 10 | Formal evaluation | Evidence-backed results, failures retained |
| 11 | Academic report | Complete report draft |
| 12 | Final readiness | Slides, rehearsals, recorded backup, packaging |

Keep research notes and report sections current every week. Week 11 is for finishing the paper,
not starting it.

## Minimum viable project

- One isolated lab, two or three target machines.
- Eight to twelve evaluation cases, including vulnerable and patched ones.
- A small curated set of Metasploit tests.
- Backend-enforced scope and explicit approval.
- Nmap discovery and structured parsing.
- Candidate matching with references and uncertainty.
- Evidence store, job status, and an audit trail.
- A fixed report template plus an AI-assisted mode.
- A basic dashboard and export.
- Reproducible experiments and the academic report.

Start with one positive case, one negative case, and one inconclusive or error case before
expanding.

## Feasibility note on hardware

The lab target images such as Metasploitable 2 are x86. Running them on an Apple Silicon Mac
needs emulation or a separate x86 host, which is slower and can behave differently. Decide the
lab host early. A small x86 machine or an authorized cloud VM is often simpler than emulation.
The live classroom demo must run offline, so the lab has to be portable to the demo laptop.

## What to cut if time runs short

Reduce the number of supported modules and interface polish first. Keep the scope controls, the
evidence quality, the baselines, and honest reporting. An honest result that AI offers little
benefit is still a valid research finding.
