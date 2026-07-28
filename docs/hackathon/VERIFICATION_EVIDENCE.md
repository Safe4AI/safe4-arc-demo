# Verification evidence

Observed in the public submission worktree on 28 July 2026 with Python 3.13.14.

## Full regression gate

Command:

```text
python -m pytest -q
```

Raw final line after the C8 wording/test update:

```text
286 passed, 7 warnings
```

## Fast gate

Command:

```text
python -m pytest -q -m "not slow"
```

Raw final line after the C8 wording/test update:

```text
60 passed, 226 deselected, 7 warnings
```

## Documentation check

Command:

```text
python scripts/check_docs.py
```

Raw result:

```text
Documentation check summary
- issues found: 0
No issues found.
```

## Public candidate audit

The final staged-file audit must report zero secrets and zero forbidden
artifacts before commit. Record the exact public commit and CI run in this file
after push.
