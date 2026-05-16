# Demo EML Examples

Synthetic `.eml` files for testing PhishGuard AI.

These emails are not real messages and are not designed to be sent. They are only demo material for local parsing, scoring and IOC extraction.

## Included cases

1. `01_legitimate_internal_security_update.eml` — benign internal communication.
2. `02_legitimate_supplier_invoice_pdf.eml` — benign invoice with PDF attachment.
3. `03_marketing_newsletter_promotional.eml` — normal newsletter/promotional email.
4. `04_spam_discount_offer_multiple_links.eml` — spam-like discount offer.
5. `05_suspicious_invoice_replyto_mismatch.eml` — suspicious finance lure with Reply-To mismatch.
6. `06_m365_credential_phishing_html.eml` — credential phishing with HTML attachment.
7. `07_parcel_delivery_ip_based_url.eml` — delivery lure using an IP-based URL.
8. `08_bec_urgent_wire_transfer_no_url.eml` — BEC-style request with pressure and no URL.
9. `09_macro_enabled_invoice_attachment.eml` — macro-enabled attachment lure.
10. `10_security_alert_punycode_homograph.eml` — punycode/homograph-style security alert.

The app can load these from the dropdown in the interface.
