# ConsentML demo — storyboard

**Goal:** in ~90 seconds, show the erasure question being answered end-to-end.
**Arc:** a subject is in two models' training data → a revocation arrives → ConsentML
names the affected models and files the dossier, and proves the record was not tampered.

All output below is real (captured 2026-08-29), not mocked.

---

### Beat 1 — the setup (~15s)
Caption: *"One decorator records what each model actually trained on."*

Show `train.py`. The eye should land on the two `@track(...)` decorators and
`source=DataFrameSource(..., subject_id_col="email")`. Both models train on a
customer table that includes `alice@example.com`.

### Beat 2 — record lineage (~10s)
```
$ python train.py
Trained churn-risk and ltv-forecast; lineage recorded.
```

### Beat 3 — the record is tamper-evident (~10s)
Caption: *"The lineage is a hash-chained audit log."*
```
$ consentml verify --db lineage.db
Audit log OK: 2 entries, chain intact.
head: 43537907536ffc04146ce0bc17e1382ce8af12864956dbb56713942eedf289b6
```

### Beat 4 — a revocation arrives (~20s)  ← the payoff
Caption: *"Alice asks to be forgotten. Which models learned from her?"*
```
$ consentml revoke --subject-id alice@example.com --db lineage.db --dry-run
2 affected models for subject ff8d9819fc0e…
  - churn-risk    run=e1084621  trained=2026-08-29T19:26:37Z  recommendation=retrain
  - ltv-forecast  run=962f16b7  trained=2026-08-29T19:26:37Z  recommendation=retrain
Dry run: nothing recorded.
```
The subject is shown as a one-way hash; raw identifiers are never stored.

### Beat 5 — file the dossier (~15s)
Caption: *"Export the document you actually file."*
```
$ consentml export --subject-id alice@example.com --db lineage.db
Wrote consentml-dossier-ff8d9819fc0e.html
```
Optional: cut to the rendered dossier in a browser for the last 3s.

### Closing card (~5s)
`pip install consentml`  ·  github.com/KaranamLokesh/consentml

---

## Optional beat — tamper detection (the differentiator, +15s)
If we want the strongest 15 seconds, insert between Beat 3 and 4:
delete a `subject_index` row directly in SQLite to hide that Alice was in a set,
then re-run `verify` and let it catch what the chain alone cannot see.
Adds SQL on screen; keep only if the longer cut is acceptable.

## Where the gif/video is used
- README (top, under the tagline)
- Blog post #1 (after the "minimal fix" section)
- Landing page hero
- Show HN post (first comment) and meetup talks
