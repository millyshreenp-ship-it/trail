from app.security.audit import AuditLog
from app.security.rbac import Perm, Principal, Role


def test_chain_intact_then_tamper_detected():
    log = AuditLog()
    for i in range(5):
        log.append("u", "r", "ACT", f"s{i}")
    assert log.verify_chain() == (True, None)
    log._entries[2]["actor"] = "mallory"
    assert log.verify_chain() == (False, 3)


def test_deleted_entry_detected():
    log = AuditLog()
    for i in range(4):
        log.append("u", "r", "ACT", f"s{i}")
    del log._entries[1]
    assert log.verify_chain()[0] is False


def test_rbac_matrix():
    assert Principal("a", Role.AUDITOR).can(Perm.AUDIT_READ)
    assert not Principal("a", Role.AUDITOR).can(Perm.CASE_APPROVE)
    assert not Principal("a", Role.L1_ANALYST).can(Perm.CASE_APPROVE)
    assert Principal("a", Role.L2_APPROVER).can(Perm.CASE_APPROVE)
    assert not Principal("a", Role.INSTITUTION_ADMIN).can(Perm.CASE_READ)  # no per-account verdicts to outsiders
