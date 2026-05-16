# Analyst Notes

## Suggested triage workflow

1. Preserve the original email with full headers.
2. Run the email through PhishGuard AI.
3. Review the risk score and evidence.
4. Validate URLs in a sandbox or URL analysis platform.
5. Validate attachments in a controlled malware-analysis environment.
6. Search for related indicators across mail gateway, SIEM and EDR logs.
7. Decide final classification:
   - Benign
   - Suspicious
   - Confirmed phishing
   - False positive
   - Insufficient evidence
8. Document final action:
   - Quarantine
   - User notification
   - Mailbox purge
   - Block sender/domain/URL/hash
   - Escalate to IR

## Common MITRE references used

- T1566.001 — Phishing: Spearphishing Attachment
- T1566.002 — Phishing: Spearphishing Link
- T1204.002 — User Execution: Malicious File
- T1110 — Brute Force / credential access context
- T1585 / T1586 — Establish / Compromise Accounts context
