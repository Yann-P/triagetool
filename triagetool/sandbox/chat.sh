#!/bin/sh
# An interactive session inside the sandbox, over attacker-controlled files.
# A first start would show a welcome that needs a host the proxy blocks, ask whether to trust this folder,
# and ask whether to use the API key. The three answers are written here so that none of them is asked.
node -e '
const key = process.env.ANTHROPIC_API_KEY || "";
const answers = {
  hasCompletedOnboarding: true,
  projects: {"/work": {hasTrustDialogAccepted: true}},
  customApiKeyResponses: {approved: [key.slice(-20)]},
};
require("fs").writeFileSync(process.env.HOME + "/.claude.json", JSON.stringify(answers));
'
exec claude --model opus --allowedTools Read,Grep,Glob,Bash --disallowedTools WebFetch,WebSearch "$@"
