# OpenCode Exit Gateway

Small OpenAI-compatible gateway for OpenCode Free models. It keeps one validated HTTP proxy exit sticky, rotates on eligible upstream responses, and replays the exact buffered request through the replacement exit. Client TLS terminates normally at Coolify/Traefik, so clients do not install a private CA.

```bash
python3 -m unittest test_gateway.py
```

Required environment: `GATEWAY_API_KEY`. Optional: `ADAPTER_URL`.
