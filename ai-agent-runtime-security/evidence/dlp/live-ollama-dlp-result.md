# Live Ollama DLP Integration Test

Date: 2026-11-13
Model: llama3.2:latest
Upstream: http://ollama:11434
Proxy: llm-egress-guard-real-test
Endpoint: POST /api/generate
Test marker: SYNTHETIC_TEST_SECRET

## Result

- Ollama upstream response: HTTP 200
- DLP client response: HTTP 403
- Detection rule: synthetic_test_secret
- Severity: HIGH
- Detection location: $.response
- Marker reached client: false
- Marker present in proxy logs: false
- Proxy audit event: response_blocked

## Conclusion

PASS. The real Ollama response containing the synthetic test marker
was blocked by the DLP proxy before it reached the client. The proxy
logged detection metadata without logging the raw marker.

This test used the real llama3.2:latest Ollama model, not a mock
upstream.
