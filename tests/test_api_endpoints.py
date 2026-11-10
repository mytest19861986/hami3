"""
Automated Verification Suite for FastAPI HTTP Endpoints
Tests:
1. Healthcheck diagnostic (/api/v1/health).
2. Geography references (/api/v1/reference/provinces & /cities).
3. Public doctors network search (/api/v1/doctors).
4. Active plans catalog (/api/v1/plans).
5. CMS informational pages (/api/v1/content/pages/terms).
6. OTP request endpoint (/api/v1/auth/otp/request).
"""

import asyncio
import uuid
import httpx

from src.api.main import app
from src.api.deps import init_pool, close_pool, init_redis, close_redis


async def test_api_suite():
    print("\n" + "=" * 70)
    print("FASTAPI HTTP ENDPOINTS AUTOMATED VERIFICATION SUITE")
    print("=" * 70)

    # Initialize pool & redis
    await init_pool()
    init_redis()

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
        # 1. Healthcheck
        print("\n[HTTP TEST 1/6] Testing GET /api/v1/health...")
        r = await client.get("/api/v1/health")
        assert r.status_code == 200, f"Expected 200, got {r.status_code}"
        data = r.json()
        assert data["status"] == "healthy"
        assert data["database"]["active"] is True
        assert data["redis"]["ping"] is True
        print(f"  ✓ Healthcheck PASS: status={data['status']}, db={data['database']['server']}, redis=OK.")

        # 2. Geography Reference
        print("\n[HTTP TEST 2/6] Testing GET /api/v1/reference/provinces & /cities...")
        r_prov = await client.get("/api/v1/reference/provinces")
        assert r_prov.status_code == 200
        provinces = r_prov.json()
        assert len(provinces) == 31
        print(f"  ✓ Provinces PASS: 31 provinces returned.")

        r_city = await client.get("/api/v1/reference/cities?province_id=1")
        assert r_city.status_code == 200
        cities = r_city.json()
        assert len(cities) > 0
        print(f"  ✓ Cities PASS: {len(cities)} cities returned for province 1.")

        # 3. Public Doctors Directory
        print("\n[HTTP TEST 3/6] Testing GET /api/v1/doctors...")
        r_docs = await client.get("/api/v1/doctors?limit=5")
        assert r_docs.status_code == 200
        docs_data = r_docs.json()
        assert "items" in docs_data
        assert "total" in docs_data
        print(f"  ✓ Doctors Directory PASS: total={docs_data['total']}, items={len(docs_data['items'])}.")

        # 4. Active Plans Catalog
        print("\n[HTTP TEST 4/6] Testing GET /api/v1/plans...")
        r_plans = await client.get("/api/v1/plans")
        assert r_plans.status_code == 200
        plans = r_plans.json()
        assert isinstance(plans, list)
        print(f"  ✓ Plans Catalog PASS: {len(plans)} active plans available.")

        # 5. CMS Informational Pages
        print("\n[HTTP TEST 5/6] Testing GET /api/v1/content/pages/terms...")
        r_cms = await client.get("/api/v1/content/pages/terms")
        assert r_cms.status_code == 200
        terms = r_cms.json()
        assert terms["slug"] == "terms"
        assert "قوانین" in terms["title"]
        print(f"  ✓ CMS Content PASS: 'terms' page retrieved successfully.")

        # 6. Auth OTP Request & Verify
        print("\n[HTTP TEST 6/10] Testing POST /api/v1/auth/otp/request & verify...")
        mobile = f"0999{uuid.uuid4().int % 10000000:07d}"
        r_otp = await client.post("/api/v1/auth/otp/request", json={"mobile": mobile})
        assert r_otp.status_code == 200
        otp_res = r_otp.json()
        assert otp_res["success"] is True
        assert 115 <= otp_res["cooldown_seconds"] <= 120
        print(f"  ✓ OTP Request PASS: cooldown={otp_res['cooldown_seconds']}s.")

        # In dev mode, OTP is logged/stored in redis
        import redis
        rd = redis.Redis.from_url("redis://localhost:6379/0", decode_responses=True)
        raw_code = rd.get(f"otp:code:{mobile}")
        assert raw_code is not None, "OTP code not found in redis"

        r_verify = await client.post("/api/v1/auth/otp/verify", json={"mobile": mobile, "code": raw_code})
        assert r_verify.status_code == 200
        verify_data = r_verify.json()
        assert "session" in verify_data
        session_token = verify_data["session"]["refresh_token"]
        auth_headers = {"Authorization": f"Bearer {session_token}"}
        print(f"  ✓ OTP Verify PASS: session_token issued.")

        # 7. Authenticated Profile Me
        print("\n[HTTP TEST 7/10] Testing GET /api/v1/profile/me...")
        r_prof = await client.get("/api/v1/profile/me", headers=auth_headers)
        assert r_prof.status_code == 200
        prof_data = r_prof.json()
        assert "has_profile" in prof_data
        print(f"  ✓ Profile Me PASS: user_id={prof_data.get('user_id')}, has_profile={prof_data['has_profile']}.")

        # 8. Authenticated Wallet Me
        print("\n[HTTP TEST 8/10] Testing GET /api/v1/wallet/me...")
        r_wal = await client.get("/api/v1/wallet/me", headers=auth_headers)
        assert r_wal.status_code == 200
        wal_data = r_wal.json()
        assert wal_data["withdrawable_balance_toman"] == 0
        assert wal_data["status"] == "ACTIVE"
        print(f"  ✓ Wallet Me PASS: balance={wal_data['withdrawable_balance_toman']}, status={wal_data['status']}.")

        # 9. Doctor Reviews Public Query
        print("\n[HTTP TEST 9/10] Testing GET /api/v1/reviews/doctor/{doctor_id}...")
        test_doc_id = docs_data["items"][0]["id"]
        r_rev = await client.get(f"/api/v1/reviews/doctor/{test_doc_id}")
        assert r_rev.status_code == 200
        rev_data = r_rev.json()
        assert "average_rating" in rev_data
        assert "total_reviews" in rev_data
        print(f"  ✓ Doctor Reviews PASS: total={rev_data['total_reviews']}, avg={rev_data['average_rating']}.")

        # 10. Authenticated Notifications
        print("\n[HTTP TEST 10/11] Testing GET /api/v1/notifications/unread-count...")
        r_notif = await client.get("/api/v1/notifications/unread-count", headers=auth_headers)
        assert r_notif.status_code == 200
        notif_data = r_notif.json()
        assert "unread_count" in notif_data
        print(f"  ✓ Notifications PASS: unread_count={notif_data['unread_count']}.")

        # 11. Root Web Portal & PWA Manifest
        print("\n[HTTP TEST 11/11] Testing GET / and /manifest.json...")
        r_root = await client.get("/")
        assert r_root.status_code == 200
        assert "حامی‌کارت" in r_root.text
        r_manifest = await client.get("/manifest.json")
        assert r_manifest.status_code == 200
        man_data = r_manifest.json()
        assert man_data["short_name"] == "حامی‌کارت"
        print(f"  ✓ Web Portal & PWA Manifest PASS: served successfully.")

    await close_pool()
    close_redis()

    print("\n" + "=" * 70)
    print("ALL 11 FASTAPI HTTP ENDPOINT TESTS PASSED (100% SUCCESS)!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_api_suite())
