"""Demo data seed script — inserts 25 realistic emails through the real analysis pipeline.

Usage:
    cd backend
    .venv\\Scripts\\python -m app.scripts.seed_demo_emails

The script is idempotent: it checks for existing analyses in the default-tenant
and skips processing if records are already present unless --force is supplied.
"""

from __future__ import annotations

import asyncio
import os
import sys
import uuid
from datetime import UTC, datetime
from typing import Any

# Ensure backend root directory is in sys.path
backend_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if backend_root not in sys.path:
    sys.path.insert(0, backend_root)

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.db.models.analysis import Analysis
from app.infrastructure.db.models.email import Email, EmailPriority, EmailStatus
from app.infrastructure.db.models.enums import AnalysisStatus
from app.infrastructure.db.models.organization import Organization
from app.infrastructure.db.session import AsyncSessionLocal
from app.services.processing.pipeline import execute_analysis_pipeline
from app.services.processing.schemas import AnalysisJob

# ─────────────────────────────────────────────────────────────────────────────
# 25 Realistic Demo Emails Across Required Categories
# ─────────────────────────────────────────────────────────────────────────────

DEMO_EMAILS: list[dict[str, Any]] = [
    # ── SAFE / LEGITIMATE ──
    {
        "category": "SAFE",
        "subject": "Q4 Budget Planning Meeting — Thursday 3pm",
        "from_address": "sarah.chen@acmecorp.com",
        "to_addresses": ["team@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Hi Team,\n\nJust a reminder that we have our Q4 budget planning meeting scheduled for "
            "Thursday at 3:00 PM in Conference Room B.\n\nAgenda:\n1. Q3 retrospective\n"
            "2. Department allocations\n3. Headcount planning\n4. Open discussion\n\n"
            "Please bring your department financial summaries.\n\n"
            "Best regards,\nSarah Chen\nDirector of Finance\nAcme Corp"
        ),
    },
    {
        "category": "SAFE",
        "subject": "Invoice #INV-2026-0892 from Standard Office Supplies",
        "from_address": "billing@standardofficesupplies.com",
        "to_addresses": ["accounts@acmecorp.com"],
        "reply_to": "ar@standardofficesupplies.com",
        "body_plain": (
            "Dear Accounts Payable Team,\n\nPlease find attached Invoice #INV-2026-0892 for office supplies "
            "delivered on October 1st, 2026.\n\nAmount Due: $1,247.50\nDue Date: October 31, 2026\n"
            "Payment Terms: Net 30\n\nPlease reference PO #4421 on all transactions.\n\n"
            "Thank you for your business.\n\nStandard Office Supplies Billing Team"
        ),
    },
    {
        "category": "SAFE",
        "subject": "Monthly Cybersecurity Dispatch — October Edition",
        "from_address": "newsletter@securitydispatch.io",
        "to_addresses": ["subscriber@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Cybersecurity Dispatch — October 2026\n\n"
            "Highlights this month:\n"
            "1. Zero-trust architectural patterns in modern infrastructure\n"
            "2. Analysis of emerging supply-chain threat vectors\n"
            "3. Best practices for secure cryptographic key rotation\n\n"
            "Read online: https://securitydispatch.io/editions/2026-10\n"
            "To manage subscriptions: https://securitydispatch.io/preferences"
        ),
    },
    {
        "category": "SAFE",
        "subject": "IT Notice: Scheduled Network Maintenance Window — Saturday 02:00 UTC",
        "from_address": "it-ops@acmecorp.com",
        "to_addresses": ["all-staff@acmecorp.com"],
        "reply_to": "servicedesk@acmecorp.com",
        "body_plain": (
            "Dear Staff,\n\nIT Operations will perform scheduled network maintenance on Saturday, "
            "October 10, between 02:00 and 04:00 UTC.\n\nExpected impact:\n"
            "- Intermittent VPN connectivity\n- Internal documentation portal maintenance\n\n"
            "Production client services will remain uninterrupted.\n\n"
            "IT Operations Team"
        ),
    },
    {
        "category": "SAFE",
        "subject": "Engineering Sync Notes & Action Items",
        "from_address": "marcus.vance@acmecorp.com",
        "to_addresses": ["dev-core@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Hi everyone,\n\nHere are the action items from today's sprint sync:\n"
            "- Marcus: Complete migration scripts review\n"
            "- Elena: Benchmark query latencies on staging\n"
            "- David: Update API documentation for v1.2 release\n\n"
            "Next sync is Monday at 10:00 AM.\n\nMarcus"
        ),
    },

    # ── PHISHING ──
    {
        "category": "PHISHING",
        "subject": "[CRITICAL] Your Microsoft 365 Account Will Be Terminated",
        "from_address": "security-alert@micros0ft-support-portal.net",
        "to_addresses": ["target.user@acmecorp.com"],
        "reply_to": "noreply@micros0ft-verify.com",
        "body_plain": (
            "MICROSOFT SECURITY TEAM ALERT\n\n"
            "Unusual login attempts have been detected on your Microsoft 365 tenant.\n"
            "Your mailbox access will be permanently revoked in 12 hours unless verified.\n\n"
            "Confirm your corporate credentials immediately:\n"
            "http://micros0ft-support-portal.net/auth/verify?session=92847aef\n\n"
            "Microsoft Cloud Identity Protection"
        ),
    },
    {
        "category": "PHISHING",
        "subject": "Google Workspace: Suspicious sign-in blocked — Action required",
        "from_address": "no-reply@accounts-google-verify.com",
        "to_addresses": ["alex.miller@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Google Security Operations\n\nA login attempt from an unknown device in Moscow, Russia was blocked.\n\n"
            "If this was not you, verify and re-authenticate your account immediately to prevent lockout:\n"
            "https://accounts-google-verify.com/recovery/verify-identity\n\n"
            "Security Team, Google Identity"
        ),
    },
    {
        "category": "PHISHING",
        "subject": "URGENT: Password Expiry Notification — Reset within 60 minutes",
        "from_address": "helpdesk@acmecorp-it-portal.net",
        "to_addresses": ["staff@acmecorp.com"],
        "reply_to": "admin@acmecorp-it-portal.net",
        "body_plain": (
            "Acme Corp IT Helpdesk Notification\n\n"
            "Your Active Directory domain password expires in 60 minutes.\n"
            "Failure to reset will disconnect all Single Sign-On integrations and remote VPN access.\n\n"
            "Reset your password now:\n"
            "https://acmecorp-it-portal.net/ad/selfservice/reset-password\n\n"
            "Acme Corporation SOC Helpdesk"
        ),
    },
    {
        "category": "PHISHING",
        "subject": "DocuSign: Please review and sign Employee Bonus Authorization 2026",
        "from_address": "documents@docus1gn-review.org",
        "to_addresses": ["employee@acmecorp.com"],
        "reply_to": "signer@docus1gn-review.org",
        "body_plain": (
            "DocuSign Electronic Signature Service\n\n"
            "HR Department has forwarded you 'Q3 Executive Incentive Authorization.pdf' for signature.\n\n"
            "REVIEW DOCUMENT:\n"
            "http://192.168.1.105/docusign/envelope/a89b4f2c\n\n"
            "Document access expires within 24 hours."
        ),
    },
    {
        "category": "PHISHING",
        "subject": "PayPal Security: Suspicious purchase of $899.99 detected",
        "from_address": "disputes@paypa1-security-center.com",
        "to_addresses": ["client@acmecorp.com"],
        "reply_to": "support@paypa1-security-center.com",
        "body_plain": (
            "PayPal Transaction Dispute Department\n\n"
            "A charge of $899.99 to 'Tech Wholesale Int.' was processed on your account.\n"
            "If you did not authorize this charge, dispute it immediately at:\n"
            "https://paypa1-security-center.com/dispute/resolve?txn=PP9920184\n\n"
            "Unconfirmed transactions are finalized after 24 hours."
        ),
    },

    # ── BUSINESS EMAIL COMPROMISE (BEC) ──
    {
        "category": "BEC",
        "subject": "CONFIDENTIAL: Urgent Wire Transfer Required for Project Horizon",
        "from_address": "ceo.harris@acmecorp-executive.com",
        "to_addresses": ["cfo@acmecorp.com"],
        "reply_to": "harris.personal.exec@protonmail.com",
        "body_plain": (
            "David,\n\nI am currently in an all-day executive board meeting and cannot take calls.\n"
            "We have reached an agreement on Project Horizon and must execute an initial escrow wire "
            "of $94,500 today to satisfy closing covenants.\n\n"
            "Beneficiary: Horizon Acquisitions LLC\n"
            "Account: 9948271034\nRouting: 021000021\nBank: Chase Commercial\n\n"
            "Please process this wire transfer immediately and email me the payment confirmation.\n"
            "Keep this strictly confidential until the official press release.\n\n"
            "Michael Harris\nChief Executive Officer"
        ),
    },
    {
        "category": "BEC",
        "subject": "Updated Remittance Banking Details — TechSupplier Corp",
        "from_address": "ar-billing@techsupplier-remit.com",
        "to_addresses": ["ap@acmecorp.com"],
        "reply_to": "finance@techsupplier-remit.com",
        "body_plain": (
            "Attention: Accounts Payable Department\n\n"
            "Please be advised that TechSupplier Corp has updated our bank depository accounts due "
            "to our annual banking audit.\n\n"
            "OLD BANK: First Commercial National\n"
            "NEW BANK: Global Commerce Trust\n"
            "Account: 3391827401\nRouting: 026009593\n\n"
            "Please update your ERP vendor records immediately and direct all pending invoice settlements "
            "to our new account starting today.\n\n"
            "Sincerely,\nAccounts Receivable Team\nTechSupplier Corp"
        ),
    },
    {
        "category": "BEC",
        "subject": "Urgent Assistance: Client Appreciation Gift Cards",
        "from_address": "director.wong@acmecorp-board.net",
        "to_addresses": ["executive.assistant@acmecorp.com"],
        "reply_to": "lisa.wong.mgmt@gmail.com",
        "body_plain": (
            "Hi,\n\nI need a quick favor. I am trapped in off-site client presentations and urgently "
            "need 10x $100 Apple Store Gift Cards for our VIP clients.\n\n"
            "Please purchase them from a nearby store, scratch the silver codes on the back, and email "
            "photos of the card numbers and PINs directly to this address.\n\n"
            "Submit the receipt to accounting for immediate petty-cash reimbursement.\n"
            "Reply as soon as you have them.\n\n"
            "Lisa Wong\nManaging Director"
        ),
    },
    {
        "category": "BEC",
        "subject": "Direct Deposit Account Update — Form W-2 / Payroll",
        "from_address": "vp.engineering@acmecorp-internal.org",
        "to_addresses": ["payroll@acmecorp.com"],
        "reply_to": "vp.eng.home@yahoo.com",
        "body_plain": (
            "Hello Payroll,\n\nI recently switched my primary checking account. Could you please update "
            "my direct deposit routing information for the upcoming pay cycle?\n\n"
            "New Details:\nBank: GreenDot Bank\nRouting: 124303120\nAccount: 8812930192\n\n"
            "Please confirm once this change is entered so my salary is routed properly.\n\n"
            "Thanks,\nMarcus Vance\nVP of Engineering"
        ),
    },

    # ── MALWARE / SUSPICIOUS ATTACHMENT ──
    {
        "category": "MALWARE",
        "subject": "DHL Delivery Failure Notice — Package #773821094",
        "from_address": "notifications@dhl-delivery-status.com",
        "to_addresses": ["warehouse@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "DHL EXPRESS INTERNATIONAL\n\n"
            "Your inbound shipment #773821094 could not be delivered due to an incorrect shipping address.\n\n"
            "Please open and complete the attached customs release form to avoid return to origin:\n"
            "Attached: DHL_Customs_Declaration_773821094.docm\n\n"
            "Note: Enable macros when prompted to generate the electronic release barcode.\n\n"
            "DHL Logistics Services"
        ),
    },
    {
        "category": "MALWARE",
        "subject": "Confidential Q3 Executive Compensation Review [Encrypted Archive]",
        "from_address": "hr-executive@talent-advisory-group.com",
        "to_addresses": ["managers@acmecorp.com"],
        "reply_to": "review@talent-advisory-group.com",
        "body_plain": (
            "Dear Manager,\n\nPlease find the encrypted executive compensation schedule for Q3.\n\n"
            "Attachment: Q3_Comp_Audit_Protected.zip\nArchive Password: 2026Executive#\n\n"
            "The archive contains an automated calculation spreadsheet (Comp_Macro_Calculator.exe).\n"
            "Run as Administrator to decrypt employee matrix data.\n\n"
            "Talent Advisory Group"
        ),
    },
    {
        "category": "MALWARE",
        "subject": "Vendor Remittance Advice & Payment Confirmation",
        "from_address": "billing@apexindustrial-parts.com",
        "to_addresses": ["finance@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Please find attached your payment remittance receipt for Invoice #8841.\n\n"
            "Attachment: Remittance_Receipt_8841.vbs\n\n"
            "Double-click to open your local accounting ledger view.\n\n"
            "Apex Industrial Parts LLC"
        ),
    },

    # ── SOCIAL ENGINEERING ──
    {
        "category": "SOCIAL_ENGINEERING",
        "subject": "[CONFIDENTIAL DISCIPLINARY NOTICE] Human Resources Case #HR-8821",
        "from_address": "compliance@acmecorp-human-resources.net",
        "to_addresses": ["target.employee@acmecorp.com"],
        "reply_to": "investigations@acmecorp-human-resources.net",
        "body_plain": (
            "PRIVATE & CONFIDENTIAL\n\n"
            "A formal workplace compliance inquiry has been initiated regarding your conduct.\n"
            "Failure to review and respond within 24 hours will result in automatic termination of employment.\n\n"
            "Do NOT discuss this with colleagues, supervisors, or department leadership.\n\n"
            "Access the formal inquiry case file:\n"
            "https://acmecorp-human-resources.net/cases/view?case_id=HR-8821&auth=9938a1\n\n"
            "Employee Relations Compliance Office"
        ),
    },
    {
        "category": "SOCIAL_ENGINEERING",
        "subject": "Internal Revenue Service: Immediate Tax Levy Notice — Warrant #884920",
        "from_address": "enforcement@irs-tax-compliance-bureau.gov.co",
        "to_addresses": ["taxpayer@acmecorp.com"],
        "reply_to": "appeals@irs-tax-compliance-bureau.gov.co",
        "body_plain": (
            "INTERNAL REVENUE SERVICE NOTICE OF LEVY\n\n"
            "Tax Identification Audit Case: #884920\n\n"
            "An outstanding balance of $4,821.50 has resulted in an automated federal tax levy.\n"
            "To halt immediate garnishment of wages and bank account freezing, resolve the balance:\n"
            "https://irs-tax-compliance-bureau.gov.co/resolution/pay?ref=884920\n\n"
            "Failure to settle within 48 hours will trigger formal judicial escalation.\n\n"
            "IRS Collections Enforcement Branch"
        ),
    },
    {
        "category": "SOCIAL_ENGINEERING",
        "subject": "EMERGENCY: Your relative has been detained — Bail required immediately",
        "from_address": "sergeant.reyes@county-detention-bureau.com",
        "to_addresses": ["family@acmecorp.com"],
        "reply_to": "bail.bureau@county-detention-bureau.com",
        "body_plain": (
            "URGENT LEGAL COMMUNICATION\n\n"
            "This is Sergeant Reyes from the County Detention Processing Center.\n"
            "Your family member was booked earlier today following a motor vehicle incident.\n"
            "Emergency bail has been posted at $2,500.00.\n\n"
            "Bail must be remitted via wire payment within 3 hours prior to state facility transfer:\n"
            "Contact desk line: +1 (555) 019-3382\n\n"
            "Do NOT call standard dispatch to avoid processing queues."
        ),
    },

    # ── SUSPICIOUS LINKS / LOOKALIKE DOMAINS ──
    {
        "category": "SUSPICIOUS_LINKS",
        "subject": "Amazon Security: Your Prime Membership has been suspended",
        "from_address": "orders-support@amaz0n-prime-security.com",
        "to_addresses": ["buyer@acmecorp.com"],
        "reply_to": "resolution@amaz0n-prime-security.com",
        "body_plain": (
            "Amazon Customer Service\n\n"
            "We were unable to process renewal for your Amazon Prime annual membership.\n"
            "Your access to Prime shipping and streaming has been paused.\n\n"
            "Verify your credit card on file:\n"
            "https://amaz0n-prime-security.com/membership/restore?user=buyer\n\n"
            "Short URL alternate access: http://bit.ly/3xAmzRenewal\n\n"
            "Amazon Billing Operations"
        ),
    },
    {
        "category": "SUSPICIOUS_LINKS",
        "subject": "Netflix: We were unable to process your recent membership payment",
        "from_address": "billing@netf1ix-billing-center.com",
        "to_addresses": ["viewer@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Netflix Billing\n\n"
            "Your subscription is currently on hold because we couldn't authorize your payment.\n"
            "Please update your card details to prevent cancellation:\n"
            "http://netf1ix-billing-center.com/account/update-card\n\n"
            "Redirect URL: http://tinyurl.com/netflix-renew-2026\n\n"
            "The Netflix Team"
        ),
    },
    {
        "category": "SUSPICIOUS_LINKS",
        "subject": "IT Security: Mandatory VPN Certificate Renewal Tool",
        "from_address": "vpn-admin@acmecorp-vpn-portal.org",
        "to_addresses": ["remote-engineers@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Corporate IT Infrastructure Notice\n\n"
            "Your GlobalProtect VPN digital root certificate expires this Friday.\n"
            "Download and execute the self-signed renewal updater below:\n"
            "https://acmecorp-vpn-portal.org/certs/renew-vpn-identity.exe\n\n"
            "If SmartScreen displays a warning, select 'More Info' and click 'Run Anyway'.\n\n"
            "Corporate Network Engineering"
        ),
    },
    {
        "category": "SUSPICIOUS_LINKS",
        "subject": "FedEx: Delivery Exception Notification — Action Needed",
        "from_address": "tracking@fedex-delivery-notice.org",
        "to_addresses": ["client@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "FedEx Delivery Notification\n\n"
            "Tracking # 98472910482910\n"
            "Status: Delivery Attempted — Customer Not Available\n\n"
            "Schedule redelivery within 48 hours to prevent return to shipper:\n"
            "http://fedex-delivery-notice.org/schedule/redelivery?id=98472910482910\n\n"
            "Mobile tracking link: http://rb.gy/fdxredeliver\n\n"
            "FedEx Express Customer Relations"
        ),
    },
    {
        "category": "SUSPICIOUS_LINKS",
        "subject": "Dropbox Business: Shared folder 'Q4 Executive Roadmaps' requires authorization",
        "from_address": "notifications@dropb0x-enterprise.net",
        "to_addresses": ["executive@acmecorp.com"],
        "reply_to": None,
        "body_plain": (
            "Dropbox for Business\n\n"
            "Sarah Chen has shared a confidential workspace folder with you: 'Q4 Executive Roadmaps'\n\n"
            "To access these encrypted assets, authenticate with your enterprise credentials:\n"
            "https://dropb0x-enterprise.net/s/view-workspace?token=a89bf20\n\n"
            "This invitation will expire in 72 hours.\n\n"
            "Dropbox Cloud Storage"
        ),
    },
]


async def _get_or_create_demo_org(session: AsyncSession) -> Organization:
    """Retrieve or create the demo organization."""
    stmt = select(Organization).where(Organization.slug == "default-tenant")
    result = await session.execute(stmt)
    org = result.scalar_one_or_none()
    if org is None:
        org = Organization(
            name="Security Operations Demo",
            slug="default-tenant",
            primary_domain="acmecorp.com",
            is_active=True,
        )
        session.add(org)
        await session.flush()
    return org


async def _count_existing_analyses(session: AsyncSession, org_id: uuid.UUID) -> int:
    """Count existing analysis records for this organization."""
    stmt = select(Analysis).where(Analysis.org_id == org_id)
    result = await session.execute(stmt)
    return len(result.scalars().all())


async def run_seed(force: bool = False) -> dict[str, Any]:
    """Execute the end-to-end seed workflow through the real pipeline."""
    results: dict[str, Any] = {
        "seeded": 0,
        "skipped": 0,
        "failed": 0,
        "total": len(DEMO_EMAILS),
        "errors": [],
    }

    async with AsyncSessionLocal() as session:
        async with session.begin():
            org = await _get_or_create_demo_org(session)
            org_id = org.id
            existing_count = await _count_existing_analyses(session, org_id)

    if existing_count > 0 and not force:
        print(f"[!] Demo organization already contains {existing_count} analyzed emails.")
        print("    Use --force to clear and re-seed.")
        results["skipped"] = len(DEMO_EMAILS)
        return results

    if force and existing_count > 0:
        print(f"[*] Clearing {existing_count} existing demo records for clean seed...")
        async with AsyncSessionLocal() as session:
            async with session.begin():
                await session.execute(delete(Analysis).where(Analysis.org_id == org_id))
                await session.execute(delete(Email).where(Email.org_id == org_id))

    print(f"\n[*] Seeding {len(DEMO_EMAILS)} emails through the real pipeline...")
    print(f"    Target Org: {org_id} (slug=default-tenant)\n")

    for i, email_spec in enumerate(DEMO_EMAILS, start=1):
        cat = email_spec["category"]
        subject = email_spec["subject"]
        from_addr = email_spec["from_address"]
        from_domain = from_addr.split("@")[-1] if "@" in from_addr else "local"

        print(f"  [{i:02d}/25] [{cat:20s}] {subject[:50]}...")

        try:
            # 1. Create DB records in isolated transaction
            async with AsyncSessionLocal() as session:
                async with session.begin():
                    email_record = Email(
                        org_id=org_id,
                        submitted_by_user_id=None,
                        message_id=f"<seed-{i:03d}-{uuid.uuid4().hex[:8]}@demo.local>",
                        subject=subject,
                        from_address=from_addr,
                        from_domain=from_domain,
                        to_addresses=email_spec.get("to_addresses", []),
                        cc_addresses=[],
                        reply_to=email_spec.get("reply_to"),
                        received_at=datetime.now(UTC),
                        body_plain=email_spec.get("body_plain"),
                        body_html=None,
                        source="demo_seed",
                        priority=EmailPriority.NORMAL,
                        status=EmailStatus.QUEUED,
                    )
                    session.add(email_record)
                    await session.flush()

                    analysis_record = Analysis(
                        email_id=email_record.id,
                        org_id=org_id,
                        status=AnalysisStatus.QUEUED,
                    )
                    session.add(analysis_record)
                    await session.flush()

                    email_id = email_record.id
                    analysis_id = analysis_record.id

            # 2. Build RFC 822 raw content
            to_str = ", ".join(email_spec.get("to_addresses", []))
            reply_header = f"Reply-To: {email_spec['reply_to']}\n" if email_spec.get("reply_to") else ""
            raw_content = (
                f"From: {from_addr}\n"
                f"To: {to_str}\n"
                f"{reply_header}"
                f"Subject: {subject}\n"
                f"MIME-Version: 1.0\n"
                f"Content-Type: text/plain; charset=utf-8\n\n"
                f"{email_spec.get('body_plain', '')}"
            )

            job = AnalysisJob(
                analysis_id=analysis_id,
                email_id=email_id,
                org_id=org_id,
                raw_content=raw_content,
            )

            # 3. Process through all genuine pipeline stages
            await execute_analysis_pipeline(job)
            results["seeded"] += 1
            print(f"         [OK] Done (analysis_id={str(analysis_id)[:8]}...)")

        except Exception as exc:
            results["failed"] += 1
            err_msg = str(exc)
            results["errors"].append({"index": i, "subject": subject, "error": err_msg})
            print(f"         [ERR] Error: {err_msg[:80]}")

    print("\n" + "=" * 60)
    print(f"Seed Summary: {results['seeded']} Seeded | {results['failed']} Failed | {results['skipped']} Skipped")
    print("=" * 60 + "\n")
    return results


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Seed realistic demo emails through the full analysis pipeline.")
    parser.add_argument("--force", action="store_true", help="Clear existing records and re-seed")
    args = parser.parse_args()

    asyncio.run(run_seed(force=args.force))
