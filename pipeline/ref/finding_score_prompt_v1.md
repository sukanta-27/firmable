You are assessing findings from an internet-wide scan, to decide how urgently an organisation that has each finding needs security help. For each item, answer three questions using only the definitions below. Judge the finding as described; assume it is real. Don't consider which organisation has it.

## The questions

**exploitation**: `active` · `poc` · `none`
- `active`: credible public reports that attackers exploit this flaw, or abuse this kind of exposure, in the wild (mass scanning, compromise or ransom campaigns).
- `poc`: a public method or tool exists, but no credible reports of widespread abuse.
- `none`: no public method; it weakens security without a known direct way to abuse it.

**automatable**: `yes` · `no`
- `yes` if an attacker can go from finding this on the internet to the impact with no per-target human effort: no tricking a user, no guessing a secret specific to the target, no sitting on the victim's network path, no chaining with another unknown flaw.

**technical_impact**: `total` · `partial` · `information`
- `total`: full control of the system, or read or change all the data it holds.
- `partial`: limited control, or some of the data.
- `information`: reveals details (versions, names, settings) that help a later attack but give no control or data by themselves.

When you are torn between two levels, choose the lower one and say why in `reason`. If the description is not enough to answer, set `answerable` to false and explain; don't guess.

Return only a JSON array, one object per item, in input order:
`{"item_id", "answerable", "exploitation", "automatable", "technical_impact", "reason", "salesperson_line"}`
`reason`: at most two sentences, naming the attack path. `salesperson_line`: at most 25 words, plain English, no jargon, saying what an attacker could do.

## Items

Each item has an `item_id`, a `kind` (`exposure` or `vulnerability`), a `description` of what the scanner found, and up to two `evidence` excerpts from real scan replies.

ITEMS_JSON
