FROM unrelated-mcp-adapter:stdio-node

RUN printf '%s\n' \
  'servers:' \
  '  everything_a:' \
  '    type: stdio' \
  '    command: npx' \
  '    args:' \
  '      - -y' \
  '      - "@modelcontextprotocol/server-everything"' \
  '  everything_b:' \
  '    type: stdio' \
  '    command: npx' \
  '    args:' \
  '      - -y' \
  '      - "@modelcontextprotocol/server-everything"' \
  > /config/config.yaml

ENV UNRELATED_CONFIG=/config/config.yaml
ENV UNRELATED_BIND=0.0.0.0:8080
ENV UNRELATED_LOG=info
ENV UNRELATED_STARTUP_TIMEOUT=180
