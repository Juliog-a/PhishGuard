# Analyst Notes

## Suggested triage workflow

1. Preserve the original email with full headers.
2. Run the email through PhishGuard AI.
3. Review the local risk score and evidence.
4. Run online IOC verification if a Worker endpoint is configured.
5. Validate URLs in a controlled sandbox or URL analysis platform before browsing.
6. For attachments, calculate hashes first and check reputation before any detonation.
7. If detonation is needed, use an isolated malware-analysis sandbox, not a production endpoint.
8. Search for related indicators across mail gateway, SIEM and EDR logs.
9. Decide final classification:
   - Benign
   - Suspicious
   - Confirmed phishing
   - False positive
   - Insufficient evidence
10. Document final action:
   - Quarantine
   - User notification
   - Mailbox purge
   - Block sender/domain/URL/hash
   - Escalate to IR

## Common MITRE references used

- T1566.001 — Phishing: Spearphishing Attachment
- T1566.002 — Phishing: Spearphishing Link
- T1204.002 — User Execution: Malicious File
- T1585 / T1586 — Establish / Compromise Accounts context
- T1598 — Phishing for Information context

## Online verification note

VirusTotal enrichment is supporting evidence, not final proof. Vendor detections, lack of detections and stale reports should be interpreted by an analyst in context.
