# 35-test verification matrix

Run the automated suite with `python -m unittest discover -s tests -v` after installing requirements. Actual results are environment dependent; the implementation status below records what was verified in this workspace.

| # | Scenario | Expected | Result in this workspace |
|---|---|---|---|
| 1 | Valid IPv4 | IP accepted | Implemented; suite could not import Flask |
| 2 | Invalid IPv4 | Rejected | Implemented; suite could not import Flask |
| 3 | Valid IPv6 | Accepted | Implemented; suite could not import Flask |
| 4 | Valid domain | Normalized | Implemented; suite could not import Flask |
| 5 | Invalid domain | Rejected | Implemented; suite could not import Flask |
| 6 | Valid URL | Syntax accepted without contact | Implemented; suite could not import Flask |
| 7 | MD5 shape | 32 hex chars accepted | Implemented; suite could not import Flask |
| 8 | SHA-1 shape | 40 hex chars accepted | Implemented; suite could not import Flask |
| 9 | SHA-256 shape | 64 hex chars accepted | Implemented; suite could not import Flask |
| 10 | CVE format | CVE-shaped value accepted | Implemented; suite could not import Flask |
| 11 | Invalid CVE | Rejected | Implemented; suite could not import Flask |
| 12 | Threat creation | Generator produces records | 2,000 CSV rows generated |
| 13 | Risk calculation | Bounded 0–100 | Implemented; suite could not import Flask |
| 14 | Confidence | Kept as distinct field | Implemented; suite could not import Flask |
| 15 | Source reliability | Per-source levels | Implemented; suite could not import Flask |
| 16 | Enrichment | Local context returned | Implemented; suite could not import Flask |
| 17 | Indicator search | Local lookup response | Implemented; suite could not import Flask |
| 18 | Correlation | Shared campaign records grouped | Implemented; suite could not import Flask |
| 19 | Duplicate observation | Dataset permits repeated indicators | Implemented; suite could not import Flask |
| 20 | Alert generation | High/critical review prompts | Implemented; suite could not import Flask |
| 21 | Alert association | Alerts join to source record | Implemented; suite could not import Flask |
| 22 | Alert status update | Allowlisted state accepted | Implemented; suite could not import Flask |
| 23 | Analyst notes | Valid local note stored | Implemented; suite could not import Flask |
| 24 | ATT&CK mapping | Selected demo mapping visible | Implemented; suite could not import Flask |
| 25 | Vulnerability scoring | CVE-shaped records risk sorted | Implemented; suite could not import Flask |
| 26 | Dashboard statistics | Counts and chart series returned | Implemented; suite could not import Flask |
| 27 | Severity filtering | Matching records only | Implemented; suite could not import Flask |
| 28 | Category filtering | Matching records only | Implemented; suite could not import Flask |
| 29 | Sorting | Allowlisted sort choices | Implemented; suite could not import Flask |
| 30 | Awareness modules | 15 modules returned | Implemented; suite could not import Flask |
| 31 | Quiz scoring | Score returned | Implemented; suite could not import Flask |
| 32 | Personalized suggestion | Recommendation returned | Implemented; suite could not import Flask |
| 33 | Empty/invalid search | Validation response | Implemented; suite could not import Flask |
| 34 | API input validation | Invalid query/state rejected | Implemented; suite could not import Flask |
| 35 | Database persistence | SQLite database stores records/notes | Implemented; suite could not import Flask |

The desktop bundled Python lacks Flask, and network package installation is unavailable in this environment. Install using the documented `requirements.txt` in a local Python environment to execute the API and suite.
