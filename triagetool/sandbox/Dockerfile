FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code
COPY agent.sh /usr/local/bin/agent
RUN chmod 755 /usr/local/bin/agent
WORKDIR /work
ENTRYPOINT ["agent"]
