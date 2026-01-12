---
description: Remove Co-Authored-By lines from the last git commit
---

Amend the most recent git commit to remove any "Co-Authored-By" lines from the commit message. Keep the rest of the commit message intact.

Use `git log -1 --format=%B` to get the current message, remove any lines starting with "Co-Authored-By:", and amend the commit with the cleaned message.
