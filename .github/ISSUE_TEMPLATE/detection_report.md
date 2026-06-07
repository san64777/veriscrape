---
name: Detection report (false positive / false negative)
about: veriscrape returned the wrong verdict for a page
title: "[detection] "
labels: detection
---

**Verdict veriscrape returned:** <!-- e.g. OK / UNVERIFIED / CHALLENGE / BLOCKED -->

**Verdict you expected:**

**Reproduction** (a non-sensitive sample helps most: a public URL, or a captured
status + headers + body with any PII or secrets removed):

```python
import veriscrape

r = veriscrape.get("https://...")
print(r.status, r.verdict, r.cause)
```

**What the page actually is** (vendor, login page, real content, SPA, etc.):

**Anything else:**
