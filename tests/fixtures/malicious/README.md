# Malicious fixtures

Hostile or evasive content files. `tests/test_malicious_fixtures.py` adds each file to a copy of
the valid corpus and asserts that the validator rejects it with the message on the file's first
line (`# expect-error: <substring>`), without crashing and within a time bound.

Nothing here is executed. The YAML is only parsed by the hardened loader. Further hostile
inputs that cannot be stored safely as plain files (oversized files, invalid UTF-8, extreme
nesting, symbolic links) are generated at test time.
