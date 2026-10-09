# AI Shield Sync — Olvrix Integration

This directory contains `ai_shield_sync.py` — the 7th bridge in the
Olvrix flywheel ecosystem.

## Integration Steps

### 1. Copy to olvrix-bridge repo

```bash
cp ai_shield_sync.py /path/to/olvrix-bridge/ai_shield_sync.py
```

### 2. Register in flywheel_orchestrator.py

```python
# In olvrix-bridge/flywheel_orchestrator.py

from .ai_shield_sync import AIShieldSync   # Add this line

class FlywheelOrchestrator:
    def __init__(self):
        self.syncs = {
            "threatfade":   ThreatFadeSync(),
            "reconos":      ReconOSSync(),
            "hezcast":      HezCastSync(),
            "fadereach":    FadeReachSync(),
            "resonaforge":  ResonaForgeSync(),
            "ai_shield":    AIShieldSync(),   # Add this line
        }
```

### 3. Wire into classifier.py

```python
# In olvrix-intelligence/classifier.py

from olvrix_bridge.ai_shield_sync import AIShieldSync
ai_shield_sync = AIShieldSync()

async def classify(self, business: dict) -> ClassificationResult:
    tasks = [
        self._lighthouse_audit(business["url"]),
        self._threatfade_scan(business["url"]),
        self._html_analysis(business["html"]),
        self._fdse_scan(business["html"]),
        self._google_enrichment(business),
        self._ai_shield_scan(business["html"], business["id"]),  # Add this
    ]
    results = await asyncio.gather(*tasks)

async def _ai_shield_scan(self, html: str, business_id: str) -> dict:
    return await ai_shield_sync.handle_business_scraped(html, business_id)
```

### 4. Wire into outreach pipeline

```python
# In olvrix-outreach/send.py — before Evolution API call

result = await ai_shield_sync.handle_outreach_generated(
    message=generated_message,
    channel="whatsapp",
    business_id=business_id,
)
if not result["safe"]:
    logger.warning("outreach_blocked_by_ai_shield", **result)
    return  # Skip this message — don't send
```

### 5. Add environment variables

```bash
# In olvrix/.env (all VPS)
AI_SHIELD_API_URL=https://api.aishield.tinlance.com
AI_SHIELD_API_KEY=your-shield-api-key
OLVRIX_TENANT_ID=olvrix-main
```

### 6. Update Olvrix Widgets bridge.py

```python
# In olvrix-widgets/apps/api/app/services/ecosystem/bridge.py
# The handler is already built. Add only the HTTP call:

async def _handle_ai_shield(self, event_type: str, payload: dict) -> None:
    async with httpx.AsyncClient() as client:
        await client.post(
            f"{settings.AI_SHIELD_API_URL}/detect/llm",
            headers={"X-API-Key": settings.AI_SHIELD_API_KEY},
            json={
                "prompt": payload.get("message_hash", ""),
                "completion": payload.get("response_hash", ""),
                "tenant_id": payload.get("client_id", ""),
                "model": "ollama-local",
            }
        )
```

## Usage Metrics

At Olvrix's target scale of 200 businesses/day:

| Event | Inferences/day | Inferences/month |
|-------|---------------|-----------------|
| Business scraped | 200 | 6,000 |
| Website generated | 200 | 6,000 |
| Outreach messages | 200 | 6,000 |
| **Total** | **600** | **~18,000** |

18,000 inferences/month fits comfortably within the Pro tier (150K/month).
Cost: $199/month — covered by first paying Olvrix client.
