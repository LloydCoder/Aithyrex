import pytest
from pydantic import ValidationError

from backend.api.routes.enforce import AllowRequest, BlockRequest


def test_block_request_accepts_bounded_model_target():
    request = BlockRequest(target_type="model", target_id="openai/gpt-4o", ttl_hours=24)
    assert request.target_id == "openai/gpt-4o"


@pytest.mark.parametrize("ttl_hours", [0, -1, 721, 1000000])
def test_block_request_rejects_unsafe_ttl(ttl_hours):
    with pytest.raises(ValidationError):
        BlockRequest(target_type="model", target_id="openai/gpt-4o", ttl_hours=ttl_hours)


@pytest.mark.parametrize("target_id", ["", "*", "model\n", "x" * 256, "../other-tenant"])
def test_block_request_rejects_invalid_target_ids(target_id):
    with pytest.raises(ValidationError):
        BlockRequest(target_type="model", target_id=target_id)


def test_block_request_rejects_unbounded_reason():
    with pytest.raises(ValidationError):
        BlockRequest(target_type="agent", target_id="agent-1", reason="x" * 501)


def test_allow_request_validates_model_identifier():
    with pytest.raises(ValidationError):
        AllowRequest(model_id="*")
