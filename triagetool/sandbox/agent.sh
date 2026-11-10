#!/bin/sh
# Runs inside the sandbox over attacker-controlled files. The host wrote task/, stdout = one JSON object.
exec claude -p "$(cat task/prompt.txt)" \
  --model "$MODEL" \
  --effort "$EFFORT" \
  --allowedTools "$TOOLS" \
  --disallowedTools WebFetch,WebSearch \
  --max-turns "$TURNS" \
  --output-format json \
  --json-schema "$(cat task/schema.json)"
