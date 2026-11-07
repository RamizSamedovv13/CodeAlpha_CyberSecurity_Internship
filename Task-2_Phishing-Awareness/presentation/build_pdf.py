from reportlab.lib.pagesizes import landscape, A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit
W, H = landscape(A4)
S = [
("Phishing Awareness Training", ["CodeAlpha Cyber Security Internship – Task 2", "Recognize, resist and report phishing.", "All brands and domains in this deck are fictional."]),
("1. Introduction to Phishing", ["Phishing tricks people into revealing credentials, paying money or running malware.", "It exploits human trust more than technical flaws.", "Channels: email, SMS, voice calls, fake websites."]),
("2. How Phishing Attacks Work", ["Bait: a convincing message.", "Hook: link, attachment or request.", "Capture: credentials, payment or malware.", "Abuse: account takeover, fraud, lateral attacks."]),
("3. Types of Phishing", ["Email phishing – mass lures posing as a brand.", "Spear phishing – targeted, personalised.", "Whaling – aimed at executives.", "Smishing – SMS.   Vishing – voice calls.", "Clone phishing – a real email copied with a malicious link."]),
("4. Social Engineering Techniques", ["Urgency and fear – deadlines and threats.", "Authority and impersonation – boss, bank, IT.", "Trust and familiarity – known names and logos.", "Curiosity and rewards – prizes, refunds, 'see this file'."]),
("5. Identifying Suspicious Emails", ["Sender domain does not match the organisation.", "Generic greeting, odd tone, spelling errors.", "Unexpected request, urgency or secrecy.", "Links whose preview differs from the text."]),
("6. Identifying Fake Websites", ["Check the domain before typing credentials.", "A padlock means encrypted, not genuine.", "Be wary of pages reached through email links.", "Unexpected requests for PIN, card or MFA codes."]),
("7. URL Analysis and Domain Spoofing", ["Real domain = the part just before the first single '/'.", "Example: northbridge.example.evil-site.example belongs to evil-site.example.", "Typosquatting: cloud1y.example vs cloudly.example.", "Extra words: northbridge-secure-login.example is not northbridge.example."]),
("8. Malicious Attachments and Links", ["Unexpected invoices, documents and archives.", "Double extensions such as .pdf.exe.", "Macros and 'enable content' prompts.", "Verify through a separate channel before opening."]),
("9. Realistic Scenarios (fictional)", ["Account suspension notice from 'Northbridge Bank'.", "Parcel fee SMS from 'Parcelo Express'.", "CEO gift-card request (business email compromise pattern).", "Bank 'fraud team' call asking for PIN."]),
("10. Prevention Best Practices", ["Use unique passwords and a password manager.", "Enable MFA; prefer passkeys or security keys.", "Keep software updated.", "Verify unusual requests out-of-band.", "Report suspicious messages."]),
("11. After Clicking a Phishing Link", ["Disconnect if you opened a file.", "Change passwords from a trusted device.", "Enable/reset MFA, review account activity.", "Report to IT/security.", "Scan the device."]),
("12. Final Knowledge Check", ["Take the 10-question interactive quiz in interactive_module/.", "Review explanations for any missed answers.", "Sources: see references/sources.md (CISA, NIST, Canadian Centre for Cyber Security, Microsoft)."]),
]
c = canvas.Canvas("phishing_awareness.pdf", pagesize=(W, H)); c.setTitle("Phishing Awareness Training")
for n, (t, bl) in enumerate(S, 1):
    c.setFillColorRGB(.04,.07,.16); c.rect(0,0,W,H,fill=1,stroke=0)
    c.setFillColorRGB(.93,.27,.27); c.rect(0,H-8,W,8,fill=1,stroke=0)
    c.setFillColorRGB(.9,.92,.97); c.setFont("Helvetica-Bold", 32); c.drawString(50, H-90, t)
    y = H-160; c.setFont("Helvetica", 20)
    for b in bl:
        lines = simpleSplit(b, "Helvetica", 20, W-140)
        c.setFillColorRGB(.23,.51,.96); c.drawString(50, y, "-")
        c.setFillColorRGB(.9,.92,.97)
        for l in lines: c.drawString(70, y, l); y -= 28
        y -= 10
    c.setFillColorRGB(.6,.66,.78); c.setFont("Helvetica", 10); c.drawString(50, 25, f"Educational use only - fictional examples   |   {n}/{len(S)}")
    c.showPage()
c.save()
