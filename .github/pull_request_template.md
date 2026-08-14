**What this changes**

**Why**

**Checklist**

- [ ] Tests cover the change, and fail without it
- [ ] `pytest --cov=consentml --cov-fail-under=100` passes with a live Postgres
- [ ] `mkdocs build --strict` passes, if docs changed
- [ ] Docs updated if behavior changed
