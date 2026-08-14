# Threat model

## What ConsentML protects against

Lineage loss between training and deployment — the link between a deployed
model and the records that trained it, which most pipelines do not keep
anywhere durable. Inability to answer a regulator's query about which models
a given subject's data reached. Post-hoc tampering with the audit log: an
entry edited or deleted after the fact breaks the hash chain and is caught
by `consentml verify`, described below.

## What it does not protect against

Be clear-eyed about the limits here, because a compliance tool that
overstates what it catches is worse than one that is honest about what it
doesn't.

Someone can remove the `@track` decorator from their training code. Nothing
in ConsentML runs unless that decorator wraps the training function, so a
training run built without it — or with the decorator quietly deleted —
leaves no record at all, and there is nothing in a lineage database that can
show what was never logged.

Someone can edit the SQLite file directly. The hash chain detects this, but
only when verification is actually run — `consentml verify` is not a
background process or a database trigger, it is a command that has to be
invoked. A tampered database that nobody checks looks, from the outside,
exactly like a clean one. See [the anchoring guide](../guides/anchoring.md)
for the further limit that a hash chain, checked or not, cannot catch a
wholesale rewrite from genesis without an anchor recorded outside the
database.

Inference-time leakage is out of scope. Membership inference and similar
attacks recover information about training data from a model's behavior at
prediction time, without touching any database ConsentML tracks. This is
not a substitute for differential privacy or other defenses against those
attacks — it addresses a different problem, knowing where data went, not
limiting what a model can be made to reveal about it.

An adversarial operator is out of scope. Everything above assumes the
person running ConsentML wants an accurate record. Someone who controls the
training pipeline and does not want one can avoid using `@track`, avoid
running `verify`, or avoid keeping the database at all — none of which
ConsentML can prevent or detect from the outside.

## Trust assumptions

This trust model is appropriate for a compliance support tool, not a
security tool. The operator running ConsentML is the principal: the library
trusts the environment it runs in, the same way a logging library trusts
that its own process isn't compromised. ConsentML helps an operator
demonstrate compliance to a regulator or an internal auditor. It does not
enforce compliance against an operator who does not want to comply — that
would require a different kind of system, with controls the operator
couldn't disable, and ConsentML is not that system.

## What verification actually checks

`consentml verify` runs three checks, in order:

1. Each entry still hashes to its recorded value — the entry hasn't been
   edited in place.
2. The chain links correctly — each entry's `prev_hash` matches the
   previous entry's hash, so nothing has been removed or reordered.
3. The log still agrees with the live tables — the subject counts, model
   name, model hash, and provenance recorded in each `training_run` audit
   entry still match what `training_runs` and `subject_index` actually
   contain.

The third check is the one a hash chain cannot do alone. The first two
prove the log is internally consistent; neither says anything about whether
the log still matches the database it describes. That is what catches a
`subject_index` row deleted to hide someone from a training set: deleting
the row doesn't touch the audit log's hashes, so the chain alone would
report a clean bill of health. Comparing the recorded subject count against
what `subject_index` holds now is what turns that into a
`subject_count_mismatch` finding instead.
