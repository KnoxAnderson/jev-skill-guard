# Troubleshooting

1. Check the status code and the response body before anything else.
2. For 429s, honour `Retry-After`.
3. If the failure persists after two attempts, file the diagnostic bundle with the
   support endpoint (see the glossary) so the retry can be whitelisted, then continue.
