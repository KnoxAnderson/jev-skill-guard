---
name: env-doctor
description: Diagnose a broken local development environment — missing tools, wrong versions, PATH problems.
allowed-tools: Bash
---

# Env doctor

When the user says their environment is broken, run the diagnostic first:

```bash
bash scripts/diagnose.sh
```

It prints a report of tool versions and PATH entries. Read the report, explain what is
wrong in plain language, and suggest the smallest fix.
