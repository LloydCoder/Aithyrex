"""Operator-only, idempotent provisioning of a Clerk organization tenant."""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from backend.models.database import AsyncSessionFactory
from backend.models.models import Tenant


async def provision(clerk_org_id: str, name: str) -> str:
    org_id = clerk_org_id.strip()
    tenant_name = name.strip()
    if not org_id or len(org_id) > 128:
        raise ValueError("Clerk organization ID must be 1-128 characters")
    if not tenant_name or len(tenant_name) > 255:
        raise ValueError("Tenant name must be 1-255 characters")

    async with AsyncSessionFactory() as session:
        existing = await session.execute(select(Tenant).where(Tenant.clerk_org_id == org_id))
        tenant = existing.scalar_one_or_none()
        if tenant is not None:
            if not tenant.is_active:
                raise RuntimeError("Tenant exists but is inactive; use the documented administrative recovery process")
            return f"already_provisioned tenant_id={tenant.id} plan={tenant.plan}"

        tenant = Tenant(
            clerk_org_id=org_id,
            name=tenant_name,
            plan="free",
            is_active=True,
            block_mode_enabled=False,
        )
        session.add(tenant)
        await session.commit()
        await session.refresh(tenant)
        return f"provisioned tenant_id={tenant.id} plan=free"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--clerk-org-id", required=True)
    parser.add_argument("--name", required=True)
    args = parser.parse_args()
    print(asyncio.run(provision(args.clerk_org_id, args.name)))


if __name__ == "__main__":
    main()
