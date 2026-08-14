# Anchoring the head hash

## The limit of a hash chain

Every entry in the audit log is hashed together with the hash of the entry
before it, so editing or deleting an entry breaks every hash that follows
it — `consentml verify` catches that by recomputing each entry's hash and
checking it against the recorded one, and checking each entry's `prev_hash`
against the entry before it. What that chain cannot detect is an attacker
with write access to the whole database who deletes the log and rebuilds it
from genesis, recomputing every hash in order as they go. The result is a
chain that is internally consistent — every hash matches its contents, every
link is correct — and passes verification cleanly. A hash chain proves
nothing in it was edited in place; on its own it can't prove the chain
you're looking at is the one that actually happened.

## Recording an anchor

`consentml verify` reports a `head_hash` — the hash of the most recent
entry — every time it runs:

```bash
consentml verify --db lineage.db
```

```
Audit log OK: 2 entries, chain intact.
head: da8c75ca4c23a5ee0c9ffd17f5e671af0bad35aa87a1b98f95d1c6486371efe4
```

Record that `head` value somewhere outside the database — a separate file, a
ticket, a secrets store, anywhere an attacker who can rewrite the database
can't also reach. That recorded value is the anchor.

## Checking it

Pass a previously recorded hash back in with `--expected-head`:

```bash
consentml verify --db lineage.db --expected-head da8c75ca4c23a5ee0c9ffd17f5e671af0bad35aa87a1b98f95d1c6486371efe4
```

```
Audit log OK: 2 entries, chain intact.
head: da8c75ca4c23a5ee0c9ffd17f5e671af0bad35aa87a1b98f95d1c6486371efe4
```

A hash that isn't present anywhere in the current chain reports
`head_mismatch` and fails verification:

```
Audit log FAILED verification: 1 finding across 2 entries.
  - [head_mismatch] tables: the anchored head is not present anywhere in the current chain; history has been rewritten or truncated
head: da8c75ca4c23a5ee0c9ffd17f5e671af0bad35aa87a1b98f95d1c6486371efe4
```

(exit code 1)

## Why membership, not equality

`--expected-head` doesn't compare the anchor against the *current* head — it
checks whether the anchor appears anywhere in the chain, from genesis to the
current tip. Take a different, freshly created database: anchor it right
after its first training run, then record a second run. Verifying against
the first run's anchor still passes, because that entry's hash is still in
the chain even though it's no longer the last one:

```bash
consentml verify --db lineage.db --expected-head cd361d1c145cf00fb2217837b0485e5b99435e7b2f00fc2f4196716764d30f6b
```

```
Audit log OK: 2 entries, chain intact.
head: 67ab7e46f61b46945676d0a7bbaf8641fd11f6a868145c2e7717020c1a2fcfe5
```

That works because each entry's hash transitively depends on every entry
before it: finding the anchor anywhere in the chain proves everything up to
that point is byte-for-byte intact, and entries appended after it are a
legitimate extension, not a mismatch. Comparing against the current head
instead — equality rather than membership — would fail on every single run
once the log had grown past the anchor point, which would train whoever's
watching the exit code to expect failure and stop trusting it. Only a
rewrite or a truncation of history, which removes the anchored entry from
the chain entirely, reports `head_mismatch`.

## What it does not prove

An anchor proves history up to the point it was taken, and nothing about
what's appended after it. A sophisticated attacker with write access can
append validly-chained forged entries past the anchor — hashed correctly,
linked correctly — and no anchor taken before those entries exists to catch
it. Re-anchor regularly to keep that unverified window small.
