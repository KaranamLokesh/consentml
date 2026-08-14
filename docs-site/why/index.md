# Why ConsentML

## The problem

Most organisations running production ML cannot answer two questions: which
deployed models were trained on a given user's data, and what evidence they
can produce that those models were addressed. This is not naivety — it is
structural. Training pipelines do not preserve the link between a deployed
artifact and the records that produced it: a model file carries no record of
which rows went into it, and the pipeline that trained it rarely keeps that
mapping anywhere durable. Reconstructing training data after the fact is
unreliable for the same reason — source tables drift. A query that pulled
one set of rows in January returns a different set in July, so re-running it
later is not the same as knowing what actually trained the model.

## Reporting, not deletion

ConsentML identifies which models a subject's data reached and records what
the operator decided to do about it. It does not modify databases, models,
or deployment infrastructure.

That boundary is deliberate, for three reasons. Legal responsibility for
what happens to a deployed model sits with the operator, not with a
library — a tool that took action on their behalf would be making decisions
that are theirs to make. "Delete a subject's influence from a trained
model" is also an open research problem, not an engineering detail: for a
scikit-learn model it means a full retrain on the remaining data, and for a
fine-tuned LLM there is no reliable answer at all. Given that, a tool that
promised deletion would be promising something it cannot deliver.

## How it differs from adjacent tools

| | What it does | How ConsentML differs |
|---|---|---|
| Compliance platforms (OneTrust, BigID, Securiti) | Configuration-driven privacy suites | Integrates at the training function, in code, not at the data lake via a dashboard |
| Lineage frameworks (OpenLineage, DataHub, Marquez) | Generic pipeline lineage | Per-subject lookup and revocation events are first-class, not built on top |
| Machine unlearning research | Modifies model weights to remove an example's influence | Operates upstream, on the lineage; identifies what would need unlearning |
| Experiment trackers (MLflow, W&B) | Reproducibility and comparison | Records lineage specifically to answer "which models learned from this person?" |

## Standards

| Standard | What ConsentML supports |
|---|---|
| NIST AI RMF | Govern (documented, transparent risk-management processes), Map (documented data provenance), MANAGE-2.3 (response plans) |
| GDPR | Article 30 records of processing; Article 17 erasure requests |
| CCPA/CPRA | Audit-trail expectations for consumer requests |

ConsentML produces the lineage records and audit trail these frameworks
expect an operator to keep. It does not certify compliance with any of
them.
