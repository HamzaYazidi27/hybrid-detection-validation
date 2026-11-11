# Reference data

Offline, pinned data used by [`tools/validate_content.py`](../validate_content.py). CI never
downloads reference data; changes arrive only through reviewed commits.

| File | Content | Pinned to | Licence |
|---|---|---|---|
| [`attack-enterprise.json`](attack-enterprise.json) | MITRE ATT&CK Enterprise: 867 technique/sub-technique IDs (706 active, 161 revoked or deprecated), names, tactics mapped to Sentinel tactic names, revocation targets | ATT&CK **20.1** from `mitre-attack/attack-stix-data` at commit `a8db2f52eb933c9c99060c123e088b3326d3a607` (`enterprise-attack/enterprise-attack-20.1.json`) | MITRE ATT&CK licence: see [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) |
| [`licensing-matrix.yml`](licensing-matrix.yml) | Per-table Log Analytics export licensing, portal availability, sources, empirical gates LIC-001…006 | Microsoft documentation read 2026-11-11 (sources listed in the file) | Project content |

## Refreshing ATT&CK data

1. Download a newer `enterprise-attack-<version>.json` from `mitre-attack/attack-stix-data` and
   note the commit SHA.
2. Regenerate the file:

   ```bash
   python tools/update_attack_data.py path/to/enterprise-attack-<version>.json --source-commit <sha>
   ```

3. Update [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md) (version, commit, release date,
   licence text at that commit).
4. Run the tests: revoked techniques used by content will now fail validation, with their
   replacement IDs.

Why the techniques are kept in full: the validator must recognise any ATT&CK ID an author might
use, and revoked or deprecated entries are what allow it to report the replacement technique.
The file is 166 KB (about 15 KB compressed), kept pretty-printed for reviewable diffs.

Mapping note: recent ATT&CK releases (already 19.2, the oldest checked) replace *Defense Evasion*
with *Stealth* and *Defense Impairment*. Both
are mapped to Sentinel's `DefenseEvasion`. This is an **unverified assumption** about Sentinel's
current tactic list (Phase 3).
