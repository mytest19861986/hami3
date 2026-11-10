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

        # 6. Auth OTP Request
        print("\n[HTTP TEST 6/6] Testing POST /api/v1/auth/otp/request...")
        mobile = f"0999{uuid.uuid4().int % 10000000:07d}"
        r_otp = await client.post("/api/v1/auth/otp/request", json={"mobile": mobile})
        assert r_otp.status_code == 200
        otp_res = r_otp.json()
        assert otp_res["success"] is True
        assert 115 <= otp_res["cooldown_seconds"] <= 120
        print(f"  ✓ OTP Request PASS: cooldown={otp_res['cooldown_seconds']}s.")

    await close_pool()
    close_redis()

    print("\n" + "=" * 70)
    print("ALL 6 FASTAPI HTTP ENDPOINT TESTS PASSED (100% SUCCESS)!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(test_api_suite())
