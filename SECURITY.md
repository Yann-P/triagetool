# Security

This repo feeds user input to a LLM, but in a Docker container isolated from the internet, with pre-built context.

Report security issues to (see my email on my GitHub profile Yann-P.)

## Two sides

Your machine runs `triagetool`. It holds your GitHub credentials, fetches the advisories and the code, launches the container, sanitizes the answer into a JSON and prints it. It never executes anything the agent produces.

The container runs the agent, assume an attacker controls what happens inside it. It can read that directory, run commands as an unprivileged user on a read-only filesystem, and reach `api.anthropic.com` through a proxy that allows nothing else. It has no GitHub token, no other network access, and cannot write to your machine.

## What can still go wrong

- The verdict can be wrong, AI should never make the last call.
- The agent can spend tokens, use a spend-limited API key
- A container escape (like docker CVE) breaks the whole security boundary of this repo.
- Unpublished advisories and private code are sent to the LLM.