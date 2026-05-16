# PhishGuard AI example emails

These `.eml` files are synthetic and safe demo samples. They are designed to exercise different risk levels in the analyzer. Do not send them as real emails.

| File | Scenario | Expected risk |
|---|---|---|
| `01_legitimate_internal_security_update.eml` | Legitimate internal security update / Actualización interna legítima | Low |
| `02_legitimate_supplier_invoice_pdf.eml` | Legitimate supplier invoice with PDF / Factura legítima con PDF | Low |
| `03_marketing_newsletter_promotional.eml` | Marketing newsletter / Newsletter promocional | Low/Medium |
| `04_spam_discount_offer_multiple_links.eml` | Spam-like discount offer / Oferta tipo spam | Medium |
| `05_suspicious_invoice_replyto_mismatch.eml` | Suspicious invoice with Reply-To mismatch / Factura sospechosa con Reply-To distinto | High |
| `06_m365_credential_phishing_html.eml` | M365 credential phishing / Phishing de credenciales M365 | Critical |
| `07_parcel_delivery_ip_based_url.eml` | Parcel delivery phishing with IP URL / Phishing de paquetería con URL por IP | High/Critical |
| `08_bec_urgent_wire_transfer_no_url.eml` | BEC-style payment request without URL / BEC con solicitud de pago sin URL | High |
| `09_macro_enabled_invoice_attachment.eml` | Macro-enabled invoice attachment / Factura con adjunto de macros | High/Critical |
| `10_security_alert_punycode_homograph.eml` | Punycode/homograph security alert / Alerta con dominio punycode | Critical |
