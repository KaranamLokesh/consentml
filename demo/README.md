# Demo

![ConsentML demo](demo.gif)

A 90-second walk-through of the full flow: record lineage for two training runs,
verify the audit log is intact, report the models affected by a revocation, and
export the dossier.

## Run it yourself

```bash
pip install consentml scikit-learn pandas
python train.py                                              # records lineage.db
consentml verify --db lineage.db                             # chain intact
consentml revoke --subject-id alice@example.com --db lineage.db --dry-run
consentml export --subject-id alice@example.com --db lineage.db --out dossier.html
```

## Regenerate the gif

Requires [`vhs`](https://github.com/charmbracelet/vhs) (`brew install vhs`) and
`consentml` on your `PATH`:

```bash
vhs demo.tape
```

See `STORYBOARD.md` for the beat-by-beat script.
