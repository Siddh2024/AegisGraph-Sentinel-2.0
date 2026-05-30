"""Regression tests for honeypot escrow lookup performance."""

from src.features.honeypot_escrow import HoneypotEscrowManager, HoneypotStatus


def test_withdrawal_attempt_uses_account_index(monkeypatch):
    manager = HoneypotEscrowManager()

    honeypot = manager.activate_honeypot(
        transaction_id="txn-386",
        source_account="source_1",
        target_account="mule_1",
        amount=100.0,
        currency="INR",
        risk_score=0.95,
        fraud_indicators=["known_mule_account"],
    )

    assert manager._active_honeypots_by_account["mule_1"] is honeypot

    alert = manager.record_withdrawal_attempt(
        account="mule_1",
        withdrawal_type="ATM",
        amount=20.0,
        location={"address": "Mumbai"},
    )

    assert alert is not None
    assert honeypot.status == HoneypotStatus.ALERT_SENT
    assert len(honeypot.withdrawal_attempts) == 1
