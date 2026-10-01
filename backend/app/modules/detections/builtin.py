"""Three bounded single-event signals, with immutable, explanatory rule metadata.

This is a fixed catalog, not a window/sequence engine or a PowerShell interpreter.
Evaluators examine source facts only; they perform no I/O and never execute input.
"""

from __future__ import annotations

import base64
import binascii
import re
import shlex
from dataclasses import dataclass
from typing import Any, Literal

EVALUATOR_VERSION = "single-event-v1"
MAX_COMMAND_LENGTH = 8192


@dataclass(frozen=True)
class BuiltinRule:
    id: str
    version: str
    title: str
    description: str
    severity: Literal["medium", "high"]
    mitre: tuple[str, ...]
    false_positive_guidance: tuple[str, ...]
    references: tuple[str, ...]

    def snapshot(self) -> dict[str, Any]:
        """Return fresh JSON values so callers cannot change catalog metadata."""
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "mitre": list(self.mitre),
            "false_positive_guidance": list(self.false_positive_guidance),
            "references": list(self.references),
            "type": "single_event",
            "evaluator_version": EVALUATOR_VERSION,
        }


BUILTIN_RULES = (
    BuiltinRule(
        id="powershell-suspicious-command",
        version="1.0.0",
        title="PowerShell: kodowane polecenie lub pobieranie i wykonanie",
        description=(
            "Proces PowerShell/pwsh z Windows 4688 lub Sysmon 1. Wykrywa parametr "
            "-EncodedCommand/-enc z niepustą wartością Base64 przed -File/-Command albo "
            "kod -Command/-c z DownloadString i IEX/Invoke-Expression lub "
            "Invoke-WebRequest/iwr przekazanym do IEX/Invoke-Expression. "
            "To sygnał do weryfikacji, bez potwierdzenia skutecznego wykonania ataku. "
            "Nie obejmuje pełnej składni, zaciemniania kodu ani treści plików skryptów."
        ),
        severity="high",
        mitre=("T1059.001",),
        false_positive_guidance=(
            "Zatwierdzone skrypty administracyjne mogą używać kodowanych poleceń.",
            "Instalatory i narzędzia zarządzania mogą pobierać oraz wykonywać skrypty.",
        ),
        references=(
            "https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/"
            "about/about_powershell_exe?view=powershell-5.1",
            "https://attack.mitre.org/techniques/T1059/001/",
        ),
    ),
    BuiltinRule(
        id="linux-root-session",
        version="1.0.0",
        title="Linux: powłoka lub sesja root przez sudo/su",
        description=(
            "Nie-rootowy użytkownik i cel root. Wykrywa zaakceptowane sudo z bezpośrednim "
            "poleceniem sh/bash/dash/zsh/ksh/fish bez skryptu ani -c (dopuszcza flagi "
            "login/interaktywne) albo otwarcie sesji root przez su. "
            "Log su potwierdza otwarcie sesji, nie wykonanie powłoki; zwykłe polecenia "
            "sudo, zamknięcia sesji i nieudane próby nie wyzwalają tej reguły."
        ),
        severity="medium",
        mitre=(),
        false_positive_guidance=(
            "Uprawniony administrator może otworzyć powłokę lub sesję root podczas obsługi.",
            "Samo otwarcie sesji nie dowodzi wykorzystania podatności ani nadużycia sudo.",
        ),
        references=("https://attack.mitre.org/techniques/T1548/003/",),
    ),
    BuiltinRule(
        id="windows-local-admin-member-added",
        version="1.0.0",
        title="Windows: dodanie członka do lokalnych Administratorów",
        description=(
            "Windows 4732, dodanie członka grupy z identyfikatorem S-1-5-32-544. "
            "Rozpoznaje SID grupy niezależnie od jej nazwy i języka. "
            "Nie wnioskuje o utworzeniu nowego konta ani o sekwencji zdarzeń. "
            "Brakujące dane członka, wykonawcy lub hosta pozostają nieznane."
        ),
        severity="high",
        mitre=("T1098.007",),
        false_positive_guidance=(
            "Zatwierdzone nadanie uprawnień lub instalacja oprogramowania może zmienić grupę.",
        ),
        references=(
            "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/"
            "security/threat-protection/auditing/event-4732",
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/"
            "understand-security-identifiers",
            "https://attack.mitre.org/techniques/T1098/007/",
        ),
    ),
)


@dataclass(frozen=True)
class Match:
    rule: BuiltinRule
    reason: dict[str, Any]


def _object(document: dict[str, Any], key: str) -> dict[str, Any]:
    value = document.get(key)
    return value if isinstance(value, dict) else {}


def _text(document: dict[str, Any], key: str, *, limit: int = MAX_COMMAND_LENGTH) -> str | None:
    value = document.get(key)
    return value if isinstance(value, str) and 0 < len(value) <= limit else None


def _basename(value: str) -> str:
    return re.split(r"[/\\]", value)[-1].casefold()


def _unquote(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _reason(code: str, summary: str, **fields: Any) -> dict[str, Any]:
    return {"code": code, "summary": summary, "matched_fields": fields}


_POWERSHELL_NAMES = frozenset({"powershell", "powershell.exe", "pwsh", "pwsh.exe"})
_PS_VALUE_FLAGS = frozenset(
    {
        "-windowstyle",
        "-w",
        "-inputformat",
        "-outputformat",
        "-executionpolicy",
        "-ep",
        "-version",
        "-psconsolefile",
        "-configurationname",
        "-workingdirectory",
    }
)
_PS_SWITCH_FLAGS = frozenset(
    {
        "-nologo",
        "-noexit",
        "-sta",
        "-mta",
        "-noprofile",
        "-nop",
        "-noninteractive",
        "-noni",
    }
)


def _powershell_arguments(command: str) -> tuple[str, str] | None:
    """Inspect only known CLI flags; -File and -Command stop argument scanning."""
    try:
        tokens = shlex.split(command, posix=False)
    except ValueError:
        return None
    if not tokens:
        return None
    if _basename(_unquote(tokens[0])) in _POWERSHELL_NAMES:
        tokens = tokens[1:]
    elif not tokens[0].startswith("-"):
        return None
    index = 0
    while index < len(tokens):
        flag = _unquote(tokens[index]).casefold()
        if flag in {"-encodedcommand", "-enc"}:
            if index + 1 >= len(tokens):
                return None
            value = _unquote(tokens[index + 1])
            try:
                decoded = base64.b64decode(value, validate=True)
            except (ValueError, binascii.Error):
                return None
            # Decode bytes solely to validate the argument. Do not interpret code.
            if not decoded or base64.b64encode(decoded).decode("ascii") != value:
                return None
            return "encoded_command_argument", value
        if flag in {"-file", "-f"}:
            return None
        if flag in {"-command", "-c"}:
            remainder = tokens[index + 1 :]
            if not remainder:
                return None
            code = _unquote(remainder[0]) if len(remainder) == 1 else " ".join(remainder)
            return "command_code", code
        if flag in _PS_SWITCH_FLAGS:
            index += 1
        elif flag in _PS_VALUE_FLAGS and index + 1 < len(tokens):
            index += 2
        else:
            # Unsupported flags do not turn later literal arguments into CLI flags.
            return None
    return None


def _code_outside_literals(script: str) -> str | None:
    """Bounded lexical signature support; skip strings/comments, reject obfuscation."""
    output: list[str] = []
    index = 0
    while index < len(script):
        character = script[index]
        if character == "`" or script[index : index + 2] in {"@'", '@"', "<#"}:
            return None
        if character == "#":
            newline = script.find("\n", index)
            if newline == -1:
                break
            output.append("\n")
            index = newline + 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            while index < len(script):
                if script[index] == "`" and quote == '"':
                    index += 2
                elif script[index] == quote:
                    if quote == "'" and script[index : index + 2] == "''":
                        index += 2
                    else:
                        index += 1
                        break
                else:
                    index += 1
            else:
                return None
            output.append(" ")
            continue
        output.append(character)
        index += 1
    return "".join(output).casefold()


_EXPRESSION_CALL = re.compile(r"(?:^|[;|({=])\s*(?:&\s+)?(?:iex|invoke-expression)\b")
_DOWNLOAD_STRING = re.compile(r"\.\s*downloadstring\s*\(")
_WEBREQUEST_CALL = re.compile(r"(?:^|[({=])\s*(?:invoke-webrequest|iwr)\b")
_EXPRESSION_PIPE = re.compile(r"\s*(?:iex|invoke-expression)\b")


def _webrequest_expression_pipeline(code: str) -> bool:
    # Split once rather than backtracking across each possible downloader call.
    # Each character belongs to one statement and one adjacent pipeline pair.
    for statement in re.split(r"[;\n]", code):
        commands = statement.split("|")
        for downloader, receiver in zip(commands, commands[1:], strict=False):
            if _WEBREQUEST_CALL.search(downloader) and _EXPRESSION_PIPE.match(receiver):
                return True
    return False


def _powershell(document: dict[str, Any]) -> dict[str, Any] | None:
    source, event = _object(document, "source"), _object(document, "event")
    process = _object(document, "process")
    if (
        source.get("type") != "windows_process"
        or event.get("category") != "process"
        or event.get("type") != "start"
        or event.get("action") != "process_started"
        or event.get("outcome") != "success"
        or event.get("code") not in ("4688", "1")
    ):
        return None
    name = _text(process, "name", limit=256)
    executable = _text(process, "executable", limit=1024)
    names = [value for value in (name, executable) if value is not None]
    if not names or any(_basename(value) not in _POWERSHELL_NAMES for value in names):
        return None
    command = _text(process, "command_line")
    if command is None:
        return None
    inspected = _powershell_arguments(command)
    if inspected is None:
        return None
    kind, value = inspected
    if kind == "encoded_command_argument":
        return _reason(
            kind,
            "Proces PowerShell uruchomiono z parametrem kodowanego polecenia Base64; "
            "treść polecenia nie została wykonana ani oceniona przez regułę.",
            **{
                "process.name": name,
                "process.executable": executable,
                "process.command_line": command,
                "event.code": event.get("code"),
            },
        )
    code = _code_outside_literals(value)
    if code is None or not (
        (_EXPRESSION_CALL.search(code) and _DOWNLOAD_STRING.search(code))
        or _webrequest_expression_pipeline(code)
    ):
        return None
    return _reason(
        "download_and_execution_indicators",
        "Polecenie PowerShell zawiera wzorzec pobierania i IEX/Invoke-Expression; "
        "log uruchomienia procesu nie potwierdza skutecznego wykonania pobranej treści.",
        **{
            "process.name": name,
            "process.executable": executable,
            "process.command_line": command,
            "event.code": event.get("code"),
        },
    )


_SHELL_NAMES = frozenset({"sh", "bash", "dash", "zsh", "ksh", "fish"})
_SHELL_FLAGS = frozenset({"-i", "-l", "-il", "-li", "--login", "--noprofile", "--norc"})


def _linux_root(document: dict[str, Any]) -> dict[str, Any] | None:
    source, event = _object(document, "source"), _object(document, "event")
    user, process = _object(document, "user"), _object(document, "process")
    actor = _text(user, "name", limit=256)
    target = _text(_object(user, "target"), "name", limit=256)
    if (
        source.get("type") != "linux_auth"
        or event.get("outcome") != "success"
        or event.get("type") != "start"
        or not actor
        or actor == "root"
        or target != "root"
    ):
        return None
    if (
        event.get("action") == "su_session"
        and event.get("category") == "authentication"
        and process.get("name") == "su"
    ):
        return _reason(
            "root_su_session_opened",
            "Użytkownik inny niż root otworzył sesję su dla root. "
            "Log sesji nie potwierdza uruchomienia powłoki ani nadużycia uprawnień.",
            **{"user.name": actor, "user.target.name": target, "event.action": "su_session"},
        )
    if not (
        event.get("action") == "sudo_command"
        and event.get("category") == "process"
        and process.get("name") == "sudo"
    ):
        return None
    command = _text(process, "command_line")
    if command is None:
        return None
    try:
        tokens = shlex.split(command, posix=True)
    except ValueError:
        return None
    if (
        not tokens
        or tokens[0].split("/")[-1] not in _SHELL_NAMES
        or any(token not in _SHELL_FLAGS for token in tokens[1:])
    ):
        return None
    return _reason(
        "sudo_root_shell_command",
        "Sudo zaakceptowało bezpośrednie polecenie powłoki dla root od innego użytkownika. "
        "Uprawniona praca administratora może dać ten sam sygnał.",
        **{
            "user.name": actor,
            "user.target.name": target,
            "process.command_line": command,
            "event.action": "sudo_command",
        },
    )


def _local_admin(document: dict[str, Any]) -> dict[str, Any] | None:
    source, event = _object(document, "source"), _object(document, "event")
    group = _object(_object(document, "extensions"), "group")
    if (
        source.get("type") != "windows_auth"
        or event.get("code") != "4732"
        or event.get("category") != "iam"
        or event.get("action") != "group_member_added"
        or event.get("outcome") != "success"
        or group.get("id") != "S-1-5-32-544"
    ):
        return None
    user = _object(document, "user")
    return _reason(
        "local_administrator_member_added",
        "Windows 4732 potwierdza dodanie członka do lokalnej grupy Administratorów "
        "(S-1-5-32-544). Reguła nie wnioskuje o utworzeniu nowego konta.",
        **{
            "event.code": "4732",
            "extensions.group.id": "S-1-5-32-544",
            "extensions.group.name": _text(group, "name", limit=256),
            "user.target.id": _text(_object(user, "target"), "id", limit=256),
            "user.id": _text(user, "id", limit=256),
            "user.name": _text(user, "name", limit=256),
        },
    )


_EVALUATORS = {
    "powershell-suspicious-command": _powershell,
    "linux-root-session": _linux_root,
    "windows-local-admin-member-added": _local_admin,
}


def evaluate_rule(rule_id: str, document: dict[str, Any]) -> list[Match]:
    rule = next((item for item in BUILTIN_RULES if item.id == rule_id), None)
    if rule is None:
        raise ValueError("unknown_builtin_rule")
    if document.get("schema_version") != "1.0":
        return []
    reason = _EVALUATORS[rule.id](document)
    return [Match(rule, reason)] if reason is not None else []


def evaluate(document: dict[str, Any]) -> list[Match]:
    """Evaluate source facts in catalog order; deployment state is a caller concern."""
    return [match for rule in BUILTIN_RULES for match in evaluate_rule(rule.id, document)]
