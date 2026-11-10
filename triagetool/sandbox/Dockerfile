FROM node:22-slim
RUN apt-get update && apt-get install -y --no-install-recommends git ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g @anthropic-ai/claude-code
COPY agent.sh /usr/local/bin/agent
COPY chat.sh /usr/local/bin/chat
RUN chmod 755 /usr/local/bin/agent /usr/local/bin/chat
WORKDIR /work
ENTRYPOINT ["agent"]
