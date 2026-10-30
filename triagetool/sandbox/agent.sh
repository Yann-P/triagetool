#!/bin/sh
# Runs inside the sandbox over attacker-controlled files. The host wrote task/, stdout = one JSON object.
exec claude -p "$(cat task/prompt.txt)" \
  --model opus \
  --effort high \
  --allowedTools Read,Grep,Glob,Bash \
  --disallowedTools WebFetch,WebSearch \
  --max-turns 30 \
  --output-format json \
  --json-schema "$(cat task/schema.json)"
