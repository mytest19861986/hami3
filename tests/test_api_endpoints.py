"""
Automated Verification Suite for FastAPI HTTP Endpoints
Tests:
1. Healthcheck diagnostic (/api/v1/health).
2. Geography references (/api/v1/reference/provinces & /cities).
3. Public doctors network search (/api/v1/doctors).
4. Active plans catalog (/api/v1/plans).
5. CMS informational pages (/api/v1/content/pages/terms).
6. OTP request & verify endpoints (/api/v1/auth/otp/request & /verify).
7..17. Full authenticated E2E integration across profile, wallet, order initiate->confirm->verify,
       doctor visit record, settlement guard, virtual card, and doctor QR verification.
"""

import asyncio
import os
import sys
import uuid
from pathlib import Path

os.environ.setdefault(
    "CARD_QR_SECRET",
    "test_hamicard_t21_integration_qr_signing_secret_min_32_chars",
)

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import httpx  # noqa: E402
import redis  # noqa: E402

from src.adapters.payment import get_runtime_payment_gateway  # noqa: E402
from src.api.deps import close_pool, close_redis, get_db_pool, init_pool, init_redis  # noqa: E402
from src.api.main import app  # noqa: E402
from src.auth.session_service import SessionService  # noqa: E402
from src.core.policy import set_policy_approval  # noqa: E402

_TEMP_E2E_POLICIES = (
    "OPEN_05_COMBINED_COMMISSION_POLICY",
    "OPEN_06_MIN_SETTLEMENT_AMOUNT_TOMAN",
    "OPEN_16_VISIT_MEDICAL_RECORD_LIMIT",
    "OPEN_18_CURRENCY_AND_ROUNDING",
)


async def test_api_suite():
    print("\n" + "=" * 70)
    print("FASTAPI HTTP ENDPOINTS AUTOMATED VERIFICATION SUITE")
    print("=" * 70)

    await init_pool()
    init_redis()
    pool = await get_db_pool()

    try:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            # 1. Healthcheck
            print("\n[HTTP TEST 1/17] Testing GET /api/v1/health...")
            r = await client.get("/api/v1/health")
            assert r.status_code == 200, f"Expected 200, got {r.status_code}"
            data = r.json()
            assert data["status"] == "healthy"
            assert data["database"]["active"] is True
            assert data["redis"]["ping"] is True
            print(f"  ✓ Healthcheck PASS: status={data['status']}, db={data['database']['server']}, redis=OK.")

            # 2. Geography Reference
            print("\n[HTTP TEST 2/17] Testing GET /api/v1/reference/provinces & /cities...")
            r_prov = await client.get("/api/v1/reference/provinces")
            assert r_prov.status_code == 200
            provinces = r_prov.json()
            assert len(provinces) == 31
            print("  ✓ Provinces PASS: 31 provinces returned.")

            r_city = await client.get("/api/v1/reference/cities?province_id=1")
            assert r_city.status_code == 200
            cities = r_city.json()
            assert len(cities) > 0
            print(f"  ✓ Cities PASS: {len(cities)} cities returned for province 1.")

            # 3. Public Doctors Directory
            print("\n[HTTP TEST 3/17] Testing GET /api/v1/doctors...")
            r_docs = await client.get("/api/v1/doctors?limit=5")
            assert r_docs.status_code == 200
            docs_data = r_docs.json()
            assert "items" in docs_data
            assert "total" in docs_data
            print(f"  ✓ Doctors Directory PASS: total={docs_data['total']}, items={len(docs_data['items'])}.")

            # 4. Active Plans Catalog
            print("\n[HTTP TEST 4/17] Testing GET /api/v1/plans...")
            r_plans = await client.get("/api/v1/plans")
            assert r_plans.status_code == 200
            plans = r_plans.json()
            assert isinstance(plans, list)
            print(f"  ✓ Plans Catalog PASS: {len(plans)} active plans available.")

            # 5. CMS Informational Pages
            print("\n[HTTP TEST 5/17] Testing GET /api/v1/content/pages/terms...")
            r_cms = await client.get("/api/v1/content/pages/terms")
            assert r_cms.status_code == 200
            terms = r_cms.json()
            assert terms["slug"] == "terms"
            assert "قوانین" in terms["title"]
            print("  ✓ CMS Content PASS: 'terms' page retrieved successfully.")

            # 6. Auth OTP Request & Verify
            print("\n[HTTP TEST 6/17] Testing POST /api/v1/auth/otp/request & verify...")
            mobile = f"0999{uuid.uuid4().int % 10000000:07d}"
            r_otp = await client.post("/api/v1/auth/otp/request", json={"mobile": mobile})
            assert r_otp.status_code == 200
            otp_res = r_otp.json()
            assert otp_res["success"] is True
            assert 115 <= otp_res["cooldown_seconds"] <= 120
            print(f"  ✓ OTP Request PASS: cooldown={otp_res['cooldown_seconds']}s.")

            rd = redis.Redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
            raw_code = rd.get(f"otp:code:{mobile}")
            assert raw_code is not None, "OTP code not found in redis"

            r_verify = await client.post("/api/v1/auth/otp/verify", json={"mobile": mobile, "code": raw_code})
            assert r_verify.status_code == 200
            verify_data = r_verify.json()
            assert "session" in verify_data
            session_token = verify_data["session"]["refresh_token"]
            auth_headers = {"Authorization": f"Bearer {session_token}"}
            print("  ✓ OTP Verify PASS: session_token issued.")

            # 7. Authenticated Profile Me
            print("\n[HTTP TEST 7/17] Testing GET /api/v1/profile/me...")
            r_prof = await client.get("/api/v1/profile/me", headers=auth_headers)
            assert r_prof.status_code == 200
            prof_data = r_prof.json()
            assert "has_profile" in prof_data
            print(f"  ✓ Profile Me PASS: user_id={prof_data.get('user_id')}, has_profile={prof_data['has_profile']}.")

            # 8. Authenticated Wallet Me
            print("\n[HTTP TEST 8/17] Testing GET /api/v1/wallet/me...")
            r_wal = await client.get("/api/v1/wallet/me", headers=auth_headers)
            assert r_wal.status_code == 200
            wal_data = r_wal.json()
            assert wal_data["withdrawable_balance_toman"] == 0
            assert wal_data["status"] == "ACTIVE"
            print(f"  ✓ Wallet Me PASS: balance={wal_data['withdrawable_balance_toman']}, status={wal_data['status']}.")

            # Prepare verified public doctor and holder in isolated test DB
            async with pool.acquire() as conn:
                if docs_data["items"]:
                    test_doc_id = docs_data["items"][0]["id"]
                else:
                    seed_doc_uid = await conn.fetchval(
                        "INSERT INTO users (mobile, status, roles, is_mobile_verified) VALUES ($1, 'ACTIVE', '{\"DOCTOR\"}', TRUE) RETURNING id",
                        f"0918{uuid.uuid4().int % 10000000:07d}",
                    )
                    await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR')", seed_doc_uid)
                    test_doc_id = str(
                        await conn.fetchval(
                            """
                            INSERT INTO doctors (
                                user_id, medical_council_code, specialty, clinic_name,
                                province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
                            ) VALUES ($1, $2, 'General', 'Public Seed Clinic', 1, 1, 'Tehran', '0217777', 'APPROVED', TRUE)
                            RETURNING id
                            """,
                            seed_doc_uid,
                            f"PUBMED-{uuid.uuid4().hex[:6]}",
                        )
                    )

            # 9. Doctor Reviews Public Query
            print("\n[HTTP TEST 9/17] Testing GET /api/v1/reviews/doctor/{doctor_id}...")
            r_rev = await client.get(f"/api/v1/reviews/doctor/{test_doc_id}")
            assert r_rev.status_code == 200
            rev_data = r_rev.json()
            assert "average_rating" in rev_data
            assert "total_reviews" in rev_data
            print(f"  ✓ Doctor Reviews PASS: total={rev_data['total_reviews']}, avg={rev_data['average_rating']}.")

            # 10. Authenticated Notifications
            print("\n[HTTP TEST 10/17] Testing GET /api/v1/notifications/unread-count...")
            r_notif = await client.get("/api/v1/notifications/unread-count", headers=auth_headers)
            assert r_notif.status_code == 200
            notif_data = r_notif.json()
            assert "unread_count" in notif_data
            print(f"  ✓ Notifications PASS: unread_count={notif_data['unread_count']}.")

            # 11. Root Web Portal, PWA Manifest & Service Worker
            print("\n[HTTP TEST 11/17] Testing GET /, /manifest.json, and /static/sw.js...")
            r_root = await client.get("/")
            assert r_root.status_code == 200
            assert "حامی‌کارت" in r_root.text
            r_manifest = await client.get("/manifest.json")
            assert r_manifest.status_code == 200
            man_data = r_manifest.json()
            assert man_data["short_name"] == "حامی‌کارت"
            r_sw = await client.get("/static/sw.js")
            assert r_sw.status_code == 200
            assert "hamicard-cache" in r_sw.text
            print("  ✓ Web Portal, Manifest & SW PASS: served successfully.")

            # Temporarily approve operational policies for positive E2E verification; reverted in finally!
            async with pool.acquire() as conn:
                for pkey in _TEMP_E2E_POLICIES:
                    await set_policy_approval(conn, pkey, "APPROVED")

            # 12. Create Order API
            print("\n[HTTP TEST 12/17] Testing POST /api/v1/payments/orders...")
            async with pool.acquire() as conn:
                holder = await conn.fetchrow(
                    """
                    INSERT INTO plan_holders (first_name, last_name, national_code, mobile)
                    VALUES ('سارا', 'راد', $1, $2) RETURNING id
                    """,
                    f"{uuid.uuid4().int % 1000000000:010d}",
                    f"0933{uuid.uuid4().int % 10000000:07d}",
                )
                holder_id = str(holder["id"])

            selected_plan = next((p for p in plans if p.get("max_visits") and p["max_visits"] >= 5), plans[0])
            order_payload = {
                "holder_id": holder_id,
                "plan_id": selected_plan["id"],
                "idempotency_key": f"IDEM-{uuid.uuid4().hex[:12]}",
                "payment_method": "GATEWAY",
                "gateway_name": "ZARINPAL",
            }
            r_order = await client.post("/api/v1/payments/orders", json=order_payload, headers=auth_headers)
            assert r_order.status_code == 200, r_order.text
            order_data = r_order.json()
            assert order_data["success"] is True
            order_id = order_data["order"]["id"]
            print(f"  ✓ Create Order PASS: order_id={order_id}, amount={order_data['order']['amount_toman']}.")

            # 13. Initiate -> Confirm Gateway -> Verify Payment API & Membership Activation
            print("\n[HTTP TEST 13/17] Testing POST /api/v1/payments/orders/{order_id}/initiate -> /verify...")
            r_init = await client.post(
                f"/api/v1/payments/orders/{order_id}/initiate",
                json={"callback_url": "https://hamicard.local/payments/callback"},
                headers=auth_headers,
            )
            assert r_init.status_code == 200, r_init.text
            authority = r_init.json()["authority"]
            get_runtime_payment_gateway().confirm_payment(authority)

            r_ver = await client.post(
                f"/api/v1/payments/orders/{order_id}/verify",
                json={"authority": authority},
                headers=auth_headers,
            )
            assert r_ver.status_code == 200, r_ver.text
            ver_res = r_ver.json()
            assert ver_res["success"] is True
            membership_id = ver_res["membership"]["id"]
            print(f"  ✓ Verify Payment PASS: membership_id={membership_id}, status={ver_res['membership']['status']}.")

            # 14. Doctor Visit Recording API (with atomic quota decrement)
            print("\n[HTTP TEST 14/17] Testing POST /api/v1/visits/record...")
            session_svc = SessionService(pool)
            async with pool.acquire() as conn:
                doc_user = await conn.fetchrow(
                    "INSERT INTO users (mobile, roles) VALUES ($1, '{\"DOCTOR\"}') RETURNING id",
                    f"0919{uuid.uuid4().int % 10000000:07d}",
                )
                await conn.execute("INSERT INTO user_roles (user_id, role_id) VALUES ($1, 'DOCTOR')", doc_user["id"])
                doc = await conn.fetchrow(
                    """
                    INSERT INTO doctors (
                        user_id, medical_council_code, specialty, clinic_name,
                        province_id, city_id, clinic_address, clinic_phone, verification_status, is_public_listed
                    ) VALUES ($1, $2, 'Cardiology', 'Heart Clinic', 1, 1, 'Tehran', '0218888', 'APPROVED', TRUE)
                    RETURNING id
                    """,
                    doc_user["id"],
                    f"MED-{uuid.uuid4().hex[:6]}",
                )
                doc_id = str(doc["id"])
                doc_sess = await session_svc.create_session(user_id=doc_user["id"], device_info="test-agent", ip_address="127.0.0.1")
                doc_headers = {"Authorization": f"Bearer {doc_sess['refresh_token']}"}

            visit_payload = {
                "doctor_id": doc_id,
                "holder_id": holder_id,
                "membership_id": str(membership_id),
                "service_title": "ویزیت تخصصی چکاپ",
                "total_amount_toman": 500000,
                "discount_percent": 25.0,
            }
            r_visit = await client.post("/api/v1/visits/record", json=visit_payload, headers=doc_headers)
            assert r_visit.status_code == 200, r_visit.text
            visit_res = r_visit.json()
            assert visit_res["success"] is True
            assert visit_res["visit"]["discount_amount_toman"] == 125000
            assert visit_res["visit"]["patient_paid_amount_toman"] == 375000
            print(f"  ✓ Record Visit PASS: visit_id={visit_res['visit']['id']}, total={visit_res['visit']['total_amount_toman']}.")

            # 15. Wallet Settlement Request API
            print("\n[HTTP TEST 15/17] Testing POST /api/v1/wallet/settle...")
            settle_payload = {
                "amount_toman": 150000,
                "bank_card_number": "6037991199999990",
                "bank_sheba_number": "IR630170000000100412345678",
                "bank_account_holder_name": "سارا راد",
            }
            r_settle = await client.post("/api/v1/wallet/settle", json=settle_payload, headers=auth_headers)
            assert r_settle.status_code == 400, r_settle.text
            assert "Insufficient funds" in r_settle.json()["detail"]
            print("  ✓ Wallet Settle PASS: Insufficient balance safely guarded with 400 Bad Request.")

            # 16. Digital Membership Card Retrieval API
            print("\n[HTTP TEST 16/17] Testing GET /api/v1/cards/membership/{membership_id}...")
            r_card = await client.get(f"/api/v1/cards/membership/{membership_id}", headers=auth_headers)
            assert r_card.status_code == 200, r_card.text
            card_data = r_card.json()
            assert card_data["success"] is True
            assert card_data["card"]["card_number"].startswith("HAMI-1405-")
            assert "HAMICARD:v1:" in card_data["card"]["qr_code_payload"]
            qr_payload = card_data["card"]["qr_code_payload"]
            print(f"  ✓ Virtual Card PASS: card_number={card_data['card']['card_number']}, qr_signed=OK.")

            # 17. Clinic Doctor QR Scan Verification API
            print("\n[HTTP TEST 17/17] Testing POST /api/v1/cards/verify-qr...")
            r_scan = await client.post("/api/v1/cards/verify-qr", json={"qr_payload": qr_payload}, headers=doc_headers)
            assert r_scan.status_code == 200, r_scan.text
            scan_data = r_scan.json()
            assert scan_data["verified"] is True
            assert scan_data["can_record_visit"] is True
            assert scan_data["card"]["status"] == "ACTIVE"
            print("  ✓ Clinic QR Verify PASS: verified=True, can_record_visit=True.")

        print("\n" + "=" * 70)
        print("ALL 17 FASTAPI HTTP ENDPOINT TESTS PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE system_settings
                SET approval_status = 'PROPOSED',
                    approved_by = NULL,
                    approved_at = NULL,
                    updated_at = NOW()
                WHERE key LIKE 'OPEN\\_%' ESCAPE '\\';
                """
            )
        await close_pool()
        close_redis()


if __name__ == "__main__":
    asyncio.run(test_api_suite())
