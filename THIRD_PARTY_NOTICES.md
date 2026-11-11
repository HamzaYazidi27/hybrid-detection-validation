# Third-Party Notices

This repository redistributes data derived from the third-party work below. The project's own
licence has not been chosen yet (see `README.md`); it does not apply to the material listed here.

## MITRE ATT&CK®

**Redistributed file:** [`tools/data/attack-enterprise.json`](tools/data/attack-enterprise.json)
(a derived subset: technique IDs, names, tactics and revocation/deprecation status).

| Item | Value |
|---|---|
| Dataset | Enterprise ATT&CK, version **20.1** (collection modified 2026-11-05T15:11:27.678Z) |
| Source repository | https://github.com/mitre-attack/attack-stix-data |
| Source file | `enterprise-attack/enterprise-attack-20.1.json` |
| Source commit (pinned) | `a8db2f52eb933c9c99060c123e088b3326d3a607` |
| Generator | [`tools/update_attack_data.py`](tools/update_attack_data.py) |
| Copyright marking in the source bundle | "Copyright 2015-2026, The MITRE Corporation. MITRE ATT&CK and ATT&CK are registered trademarks of The MITRE Corporation." |

### Licence (reproduced verbatim from `LICENSE.txt` at the pinned commit)

```text
License
-------
The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research,
development, and commercial purposes. Any copy you make for such purposes is authorized provided that you reproduce
MITRE's copyright designation and this license in any such copy.

"© 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation."

Disclaimers
-----------
MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part
of its adversary model and framework of techniques. Using the information contained within ATT&CK to address or cover
full categories of techniques will not guarantee full defensive coverage as there may be undisclosed techniques or
variations on existing techniques not documented by ATT&CK.

ALL DOCUMENTS AND THE INFORMATION CONTAINED THEREIN ARE PROVIDED ON AN "AS IS" BASIS AND THE CONTRIBUTOR, THE
ORGANIZATION HE/SHE REPRESENTS OR IS SPONSORED BY (IF ANY), THE MITRE CORPORATION, ITS BOARD OF TRUSTEES, OFFICERS,
AGENTS, AND EMPLOYEES, DISCLAIM ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT
THE USE OF THE INFORMATION THEREIN WILL NOT INFRINGE ANY RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR
FITNESS FOR A PARTICULAR PURPOSE.
```

MITRE's Terms of Use: https://attack.mitre.org/resources/terms-of-use/

The copyright marking is also embedded in the redistributed JSON file (`copyright` field), and
the generator refuses to produce data from a bundle without a copyright marking. When ATT&CK data
is regenerated from a newer release, update this file with the new version, commit, release date
and the licence text found at that commit. `tests/test_reference_data.py` checks that the version
and commit here match the data file.

## Not redistributed

Development tools used by CI (PyYAML, jsonschema, pytest, yamllint, actionlint-py, gitleaks,
GitHub Actions) are **downloaded at build time** from their official sources and are not included
in this repository; their licences apply to those downloads. Short quotations from Microsoft
documentation in `docs/` are cited with their source URLs.
