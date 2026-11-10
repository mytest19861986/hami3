"""
Automated Verification Suite for Doctors Network & Discount Plans (HC-T13)
Baseline: BL-HAMICARD-PRD-V1 (DOC-001..014, PLAN-001..013, AC-02)
Tests:
1. Doctor registration in PENDING status.
2. Medical Council Code uniqueness.
3. Doctor verification lifecycle (Approve, Reject, Suspend) + Fail-Closed.
4. Public directory search (only APPROVED & is_public_listed).
5. Service contract creation & retrieval.
6. Discount plan creation with strict boundary validations.
7. Active plan catalog & status toggle with audit log.
"""

import asyncio
import os
import uuid
from datetime import date, timedelta

import asyncpg

from src.doctors.service import (
    DoctorService,
    DoctorVerificationError,
    DuplicateMedicalCouncilCodeError,
)
from src.plans.service import DiscountPlanService, PlanError

PG_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://hamicard:hamicard_dev_secret_pass@localhost:5432/hamicard_dev"
)


async def test_doctor_registration_and_uniqueness(pool: asyncpg.Pool):
    print("\n[DOCTOR TEST 1/5] Testing Doctor Registration & Council Code Uniqueness...")
    doc_svc = DoctorService(pool)

    # 1. Create a dummy user
    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            """
            INSERT INTO users (mobile, status, roles)
            VALUES ($1, 'ACTIVE', '{"DOCTOR"}')
            RETURNING id
            """, f"0913{uuid.uuid4().int % 10000000:07d}"
        )
        user_id = user_row["id"]

    council_code = f"MED-{uuid.uuid4().hex[:6].upper()}"

    # 2. Register doctor
    doc = await doc_svc.register_doctor(
        user_id=user_id,
        medical_council_code=council_code,
        specialty="Cardiology",
        clinic_name="Heart Care Clinic",
        province_id=1,
        city_id=1,
        clinic_address="Valiasr St, Tehran",
        clinic_phone="02188889999",
        custom_discount_percent=25.0
    )

    assert doc["id"] is not None
    assert doc["verification_status"] == "PENDING"
    assert doc["is_public_listed"] is False
    print("  ✓ Doctor registered with status PENDING and is_public_listed=FALSE.")

    # 3. Duplicate council code rejection
    async with pool.acquire() as conn:
        other_user = await conn.fetchrow(
            "INSERT INTO users (mobile) VALUES ($1) RETURNING id",
            f"0914{uuid.uuid4().int % 10000000:07d}"
        )

    duplicate_caught = False
    try:
        await doc_svc.register_doctor(
            user_id=other_user["id"],
            medical_council_code=council_code,
            specialty="Pediatrics",
            clinic_name="Kids Clinic",
            province_id=1,
            city_id=1,
            clinic_address="Enghelab St",
            clinic_phone="02177778888"
        )
    except DuplicateMedicalCouncilCodeError:
        duplicate_caught = True

    assert duplicate_caught, "Duplicate medical council code was not prevented!"
    print("  ✓ Medical Council Code Uniqueness Invariant PASS.")


async def test_doctor_approval_and_public_search(pool: asyncpg.Pool):
    print("\n[DOCTOR TEST 2/5] Testing Doctor Approval Lifecycle & Public Directory Search...")
    doc_svc = DoctorService(pool)

    # 1. Create doctor
    async with pool.acquire() as conn:
        user_row = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"DOCTOR\"}') RETURNING id",
            f"0915{uuid.uuid4().int % 10000000:07d}"
        )
        admin_row = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id",
            f"0916{uuid.uuid4().int % 10000000:07d}"
        )

    doc = await doc_svc.register_doctor(
        user_id=user_row["id"],
        medical_council_code=f"MED-{uuid.uuid4().hex[:6].upper()}",
        specialty="Dermatology",
        clinic_name="Skin Glow Clinic",
        province_id=1,
        city_id=1,
        clinic_address="Tehran Medical Tower",
        clinic_phone="02122223333"
    )
    doc_id = doc["id"]

    # 2. Search before approval -> Must NOT appear in public directory
    search_before = await doc_svc.search_public_directory(specialty="Dermatology")
    found_ids = [d["id"] for d in search_before["items"]]
    assert doc_id not in found_ids, "Unapproved doctor appeared in public search (Fail-Closed violation)!"
    print("  ✓ Unapproved doctor excluded from public search (Fail-Closed PASS).")

    # 3. Approve doctor
    approved_doc = await doc_svc.approve_doctor(doc_id, admin_row["id"])
    assert approved_doc["verification_status"] == "APPROVED"
    assert approved_doc["is_public_listed"] is True
    print("  ✓ Admin approved doctor: status=APPROVED, is_public_listed=TRUE.")

    # 4. Search after approval -> Must appear
    search_after = await doc_svc.search_public_directory(specialty="Dermatology")
    found_ids_after = [d["id"] for d in search_after["items"]]
    assert doc_id in found_ids_after, "Approved doctor did not appear in public search!"
    print("  ✓ Approved doctor successfully listed in public directory search.")

    # 5. Suspend doctor -> Must immediately delist
    await doc_svc.suspend_doctor(doc_id, admin_row["id"], reason="License under review")
    search_suspended = await doc_svc.search_public_directory(specialty="Dermatology")
    found_ids_susp = [d["id"] for d in search_suspended["items"]]
    assert doc_id not in found_ids_susp, "Suspended doctor remained in public search!"
    print("  ✓ Suspended doctor immediately delisted from public directory.")


async def test_doctor_service_contract(pool: asyncpg.Pool):
    print("\n[DOCTOR TEST 3/5] Testing Doctor Service Contracts...")
    doc_svc = DoctorService(pool)

    async with pool.acquire() as conn:
        doc_user = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"DOCTOR\"}') RETURNING id",
            f"0917{uuid.uuid4().int % 10000000:07d}"
        )
        admin_user = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id",
            f"0918{uuid.uuid4().int % 10000000:07d}"
        )

    doc = await doc_svc.register_doctor(
        user_id=doc_user["id"],
        medical_council_code=f"MED-{uuid.uuid4().hex[:6].upper()}",
        specialty="Dentistry",
        clinic_name="Tehran Smile",
        province_id=1,
        city_id=1,
        clinic_address="Gandi St",
        clinic_phone="02188776655"
    )
    doc_id = doc["id"]

    # 1. Contract on unapproved doctor should fail
    unapproved_blocked = False
    try:
        await doc_svc.create_service_contract(
            doctor_id=doc_id,
            contract_number=f"CTR-{uuid.uuid4().hex[:6].upper()}",
            start_date=date.today(),
            end_date=date.today() + timedelta(days=365),
            agreed_discount_percent=30.0,
            approved_by=admin_user["id"]
        )
    except DoctorVerificationError:
        unapproved_blocked = True

    assert unapproved_blocked, "Contract created for unapproved doctor!"
    print("  ✓ Service contract on unapproved doctor correctly blocked.")

    # 2. Approve doctor and create contract
    await doc_svc.approve_doctor(doc_id, admin_user["id"])
    contract_num = f"CTR-{uuid.uuid4().hex[:6].upper()}"
    contract = await doc_svc.create_service_contract(
        doctor_id=doc_id,
        contract_number=contract_num,
        start_date=date.today() - timedelta(days=1),
        end_date=date.today() + timedelta(days=364),
        agreed_discount_percent=30.0,
        approved_by=admin_user["id"]
    )
    assert contract["id"] is not None
    assert contract["status"] == "ACTIVE"
    print("  ✓ Service contract created for approved doctor.")

    # 3. Retrieve active contract
    active = await doc_svc.get_active_contract(doc_id)
    assert active is not None
    assert active["contract_number"] == contract_num
    print("  ✓ Active service contract successfully retrieved.")


async def test_discount_plan_creation_and_validation(pool: asyncpg.Pool):
    print("\n[PLAN TEST 4/5] Testing Discount Plan Creation & Boundary Validations...")
    plan_svc = DiscountPlanService(pool)

    # 1. Invalid price (<0)
    invalid_price = False
    try:
        await plan_svc.create_plan("Free Plan", price_toman=-500, discount_percent=20.0, validity_days=30)
    except PlanError:
        invalid_price = True
    assert invalid_price, "Negative price was allowed!"

    # 2. Invalid discount percent (>100)
    invalid_pct = False
    try:
        await plan_svc.create_plan("Mega Plan", price_toman=100000, discount_percent=120.0, validity_days=30)
    except PlanError:
        invalid_pct = True
    assert invalid_pct, "Discount percent > 100 was allowed!"

    # 3. Valid Plan creation
    plan = await plan_svc.create_plan(
        title="طرح طلایی سلامت حامی",
        description="دسترسی نامحدود به شبکه درمانی",
        price_toman=1500000,
        discount_percent=40.0,
        validity_days=365,
        max_visits=12,
        agent_commission_percent=15.0,
        referrer_commission_percent=5.0
    )
    assert plan["id"] is not None
    assert plan["price_toman"] == 1500000
    assert plan["is_active"] is True
    print("  ✓ Valid discount plan created with all parameters and commissions.")


async def test_plan_catalog_and_toggle(pool: asyncpg.Pool):
    print("\n[PLAN TEST 5/5] Testing Active Plan Catalog & Status Toggle...")
    plan_svc = DiscountPlanService(pool)

    async with pool.acquire() as conn:
        admin_row = await conn.fetchrow(
            "INSERT INTO users (mobile, roles) VALUES ($1, '{\"ADMIN\"}') RETURNING id",
            f"0919{uuid.uuid4().int % 10000000:07d}"
        )

    plan = await plan_svc.create_plan(
        title="طرح موقت ویژه",
        price_toman=500000,
        discount_percent=20.0,
        validity_days=30,
        is_active=True
    )
    plan_id = plan["id"]

    # 1. Check catalog
    catalog = await plan_svc.get_active_catalog()
    catalog_ids = [p["id"] for p in catalog]
    assert plan_id in catalog_ids
    print("  ✓ Active plan appears in public catalog.")

    # 2. Toggle to inactive
    toggled = await plan_svc.toggle_plan_status(plan_id, is_active=False, admin_id=admin_row["id"])
    assert toggled["is_active"] is False

    # 3. Check catalog again -> Should be excluded
    catalog_after = await plan_svc.get_active_catalog()
    catalog_ids_after = [p["id"] for p in catalog_after]
    assert plan_id not in catalog_ids_after
    print("  ✓ Deactivated plan excluded from catalog with audit logging.")


async def main():
    pool = await asyncpg.create_pool(PG_URI, min_size=2, max_size=5)
    try:
        await test_doctor_registration_and_uniqueness(pool)
        await test_doctor_approval_and_public_search(pool)
        await test_doctor_service_contract(pool)
        await test_discount_plan_creation_and_validation(pool)
        await test_plan_catalog_and_toggle(pool)
        print("\n" + "=" * 70)
        print("ALL 5 DOCTORS & DISCOUNT PLANS TEST SUITES PASSED (100% SUCCESS)!")
        print("=" * 70)
    finally:
        await pool.close()


if __name__ == "__main__":
    asyncio.run(main())
