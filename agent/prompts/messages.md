# Messages during a conversation

Each `## name` section is one message; `{...}` is filled in by noise-agent.py.

## propose-row

Total events over {since}: {total}. The row ({share} of them):
{row}
Investigate it as the rules say, then call submit.

## validate-filter

Total events over {since}: {total}. The filter to review:
{filter}
Investigate, then call verdict.

## submit-failed

These fail the code checks and would be dropped:
{failed}
Fix or remove them and call submit again with the full list.

## submit-nudge

Call submit now (an empty filters list is fine).

## verdict-nudge

Call verdict now.

## two-turns-left

Two turns left. Wrap up: {nudge}

## thinking-cut-off

You ran out of room thinking. Think briefly and call a tool now. {nudge}

## out-of-turns

You are out of turns or time. {nudge}
