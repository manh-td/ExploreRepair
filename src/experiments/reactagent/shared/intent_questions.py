from dataclasses import dataclass

MAX_CONSTRAINTS = 5

NO_VULN_NOTE = """You are NOT looking for a bug and must not name one. Describe what this code is \
supposed to do and what should hold; someone else decides what is broken. A report that says "this \
is vulnerable to X" is a failed report - say what the rule is, not where it is violated."""

RECORD_NOTE = """Deliver your findings with `record_intent`, in one call, before you finish. \
That call is the only thing anyone else sees - your closing reply is discarded, so a reply saying \
the work is done delivers nothing. Put the findings themselves in it, not an account of having \
made them."""

CITE_NOTE = """Cite file:line for every claim, from a file you actually read. A claim you cannot \
cite is dropped before anyone sees this, so an uncited guess costs you the claim and helps nobody. \
If you could not establish something, say so plainly instead of filling the gap."""

DOMAIN_PROMPT = f"""## Your part: what this code implements
Identify the specification, protocol, format, or API contract this code implements, and what \
governs its correct behaviour.

Whatever this project is, something defines what "correct" means for it. Find what that is here \
rather than assuming a kind of software: it may be an external standard the project implements, a \
contract it publishes to its own callers, or only the expectations its own documentation and tests \
record.

Look for it, do not infer it: references in comments and docstrings, links in documentation, the \
names of conformance or compatibility tests, version and capability constants, the wording of error \
messages. If the repo names an external authority, quote where. If it has none beyond its own \
documentation, say that - that is a real answer, not a gap.

Finish with: what the code implements, what governs it, where the repo says so, and which parts of \
that contract bear on safety.
{CITE_NOTE}
{RECORD_NOTE}
{NO_VULN_NOTE}"""

ACTORS_PROMPT = f"""## Your part: who reaches this code, and with what trust
List the distinct parties whose input or calls reach the location you were given, and how far each \
is trusted.

Derive the parties from this code, not from a list of usual ones - they may be roles the project \
models explicitly, or they may be implicit: whoever supplies each input the code consumes, directly \
or through the callers above it.

Trace it: who reaches the location, what they pass, where that value originated, what it passed \
through on the way. For each party, say what the code currently lets it do and on what evidence the \
code treats it as it does.
{CITE_NOTE}
{RECORD_NOTE}
{NO_VULN_NOTE}"""

RESOURCES_PROMPT = f"""## Your part: what is acted on, and what already guards it
List what the location reads, writes, creates, or hands to something else. Take the categories \
from what this code actually touches rather than from a checklist.

For each, record what operations happen to it here, and what the codebase ALREADY does around it: \
the checks, conversions, permission tests and constraints that exist before or after the \
operation. Look at how \
sibling code paths in this repo handle the same resource - a convention the rest of the project \
follows is part of what this code is supposed to do.
{CITE_NOTE}
{RECORD_NOTE}
{NO_VULN_NOTE}"""

TRUST_CONSTRAINTS = f"""## Your part: the rules that keep untrusted input in its place
Write the rules this code must satisfy about TRUST, given what the earlier parts established. At \
most {MAX_CONSTRAINTS}. Fewer is better than padded - one well-grounded rule beats five stretched \
ones.

A rule here is not about being correct in general. It is about what a party outside the trust \
boundary must not be able to cause. Work from the actors you identified: for each value that \
reaches this code from one of them, say what must be true of it before it is used, and which \
operation must never act on it unchecked.

Good rules answer: which values here are chosen by a party the code does not fully trust; what has \
to hold of such a value before the operation that consumes it; where a value used for a decision \
has to come from rather than simply being taken as given; and which of these the code does enforce \
against which the earlier parts could not find. A rule names the specific values, operations and \
call sites you read, so that someone could check it against the code and say whether it holds. "The \
input must be validated" names none of those and is not a rule.

Say plainly where you could not establish whether a check exists; an honest gap is more useful than \
a confident guess.
{{CITE_NOTE}}
{{RECORD_NOTE}}
{{NO_VULN_NOTE}}"""

CONSTRAINTS_PROMPT = TRUST_CONSTRAINTS


@dataclass(frozen=True)
class Stage:
    key: str
    title: str
    prompt: str
    max_steps: int


STAGES = (
    Stage("domain", "What this code implements", DOMAIN_PROMPT, 25),
    Stage("actors", "Who reaches it, and with what trust", ACTORS_PROMPT, 30),
    Stage("resources", "What is acted on, and what already guards it", RESOURCES_PROMPT, 30),
    Stage("constraints", "The rules that should hold", CONSTRAINTS_PROMPT, 25),
)


if __name__ == "__main__":
    for stage in STAGES:
        print("=" * 100 + f"\n{stage.key}: {stage.title}\n" + "=" * 100)
        print(stage.prompt + "\n")
