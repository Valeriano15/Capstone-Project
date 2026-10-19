# Team onboarding: read me first

If you just cloned this repository, this page is your starting point. It is a full brief on the
course, the project, the rules, and what we are building. Read it top to bottom once, then keep
it as a reference.

## 1. The course

- Course: CYB 691 Cybersecurity Capstone, Pace University, Seidenberg School.
- Term: Fall 2026, 3 credits. Lecture on Thursday evenings.
- Instructor: Danny Dimoski.
- This is the final requirement of the MS in Cybersecurity.

Budget roughly 8 to 12 hours per week per person, mostly Thursday evening through Sunday.

### How the grade is built

| Component | Weight |
| --- | --- |
| Four group progress reports | 40 percent |
| IEEE-referenced paper, 20 to 25 pages | 30 percent |
| Group presentation with a live demo of the AI component | 20 percent |
| Participation | 10 percent |

### Dates to protect

| Milestone | Date |
| --- | --- |
| Topic chosen | 16 Sep 2026 |
| Progress report | 29 Oct 2026 |
| Progress report | 12 Nov 2026 |
| Draft for feedback only, worth zero | 19 Nov 2026 |
| Final report and presentation day, report due 23:59 | 17 Dec 2026 |

### Hard submission rules

- File names must follow `GROUP#-CYB691-AssignmentN(-Surname)`. A non-compliant name scores zero.
- Accepted formats: Word, Excel, PowerPoint, PDF.
- The paper must include a dedicated AI Integration Section covering the model used, why it was
  chosen, how it changed the workflow, its security risks, and adversarial-testing results.
- The demo has to run live and offline on a laptop in the classroom. Plan for no internet.

## 2. The project in one paragraph

We are building a private, human-supervised lab application that assists selected phases of an
authorized penetration test and then helps draft the security report. It runs Nmap discovery,
matches candidate vulnerabilities, requires a human to approve each test, runs a small
allowlisted set of Metasploit validations, stores the evidence, and then produces both a
fixed-template report and an AI-assisted draft for a human to review and export. The AI only
writes report text from stored evidence. It never launches a test or invents a finding.

## 3. The research question

> Does a human-supervised, AI-assisted Metasploit workflow reduce assessment and reporting
> effort while maintaining evidence accuracy in a controlled lab?

We answer it by comparing three conditions on the same evidence bundle:

| Condition | Testing | Report |
| --- | --- | --- |
| A, manual | A person runs the tools | A person writes the report |
| B, automated no AI | The app runs the approved procedures | Fixed-template report, human reviewed |
| C, automated with AI | Same testing as B | AI-assisted draft, human reviewed |

If B and C use the same detection logic, we do not credit AI for any detection difference. AI is
measured only on its effect on reporting.

## 4. Rules of engagement, the short version

This is lab software for authorized targets only.

- The backend enforces scope. A checkbox is never the control.
- Approval binds a target, a module, and parameters. Change any of them and approval resets.
- An unapproved test stays unexecuted and is labeled not tested.
- A timeout or a failed check never means a system is safe.
- The AI model has no power to authorize or run anything.
- Out of scope for the whole project: persistence, credential harvesting, evasion, destructive
  tests, denial of service, and writing new exploits.

Full detail is in [rules-of-engagement.md](rules-of-engagement.md).

## 5. What good work looks like here

- Every finding links to its raw evidence and records how it was interpreted.
- Missing values stay unknown. We never invent a CVSS score to fill a report.
- We keep three kinds of status separate: job state, finding interpretation, and report state.
- Untrusted text such as scan banners and web page content is treated as data, never as
  instructions to the app or the model.
- We preserve failures and inconclusive results instead of hiding them.

## 6. First milestone to aim for

A teammate can reproduce a scoped discovery, approve one reviewed validation procedure, inspect
the resulting evidence, and generate a fixed-template report, with a negative or failed result
shown honestly. This milestone needs no AI and no fancy dashboard. Get here first.

## 7. Where to go next

- [architecture.md](architecture.md) for the components and trust boundaries.
- [roadmap.md](roadmap.md) for the build order and the known prototype bug.
- [roles.md](roles.md) for who owns what.
- [references.md](references.md) for the standards and tool docs.
- [glossary.md](glossary.md) if a term is unfamiliar.
