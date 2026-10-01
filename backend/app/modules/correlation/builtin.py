"""Versioned example rules describe observed sequences, not a confirmed attack."""

from app.core.errors import ApiError
from app.modules.correlation.contracts import Condition, CorrelationRule, Pattern, Stage


def eq(field: str, value: str) -> Condition:
    return Condition(field=field, operator="equals", value=value)


AUTH_FAILURE = Condition(
    all=[eq("event.category", "authentication"), eq("event.outcome", "failure")]
)
AUTH_SUCCESS = Condition(
    all=[eq("event.category", "authentication"), eq("event.outcome", "success")]
)
POWERSHELL = Condition(
    all=[
        Condition(any=[eq("event.category", "process"), eq("event.type", "process_start")]),
        Condition(
            any=[
                eq("process.name", value)
                for value in ("powershell.exe", "pwsh.exe", "powershell", "pwsh")
            ]
        ),
    ]
)
ADMIN_ADDED = Condition(
    all=[
        eq("event.code", "4732"),
        Condition(
            any=[
                eq("extensions.group.id", "S-1-5-32-544"),
                eq("extensions.target_group_sid", "S-1-5-32-544"),
            ]
        ),
    ]
)
OUTBOUND = Condition(
    all=[
        eq("event.category", "network"),
        Condition(
            any=[
                eq("event.action", "outbound_connection"),
                Condition(
                    all=[eq("event.action", "connection"), eq("extensions.direction", "outbound")]
                ),
            ]
        ),
    ]
)
GUIDANCE = [
    "Korelacja jest kandydatem do oceny analityka, nie potwierdzeniem ataku.",
    "Sprawdź testy administracyjne, automatyczne ponowienia i zakres tożsamości encji.",
    "Sprzeczne znane identyfikatory sesji po logowaniu wykluczają dopasowanie.",
    "Nazwa konta bez realm oraz PID bez process.entity_id nie są stabilną tożsamością.",
    "Windows łączymy po realm, nazwie i hoście; sprzeczne znane SID wykluczają dopasowanie.",
    "Generic/Linux zachowują dokładne ID lub realm/nazwę; ID i nazwa są osobnymi typami klucza.",
]

BUILTIN_RULES = (
    CorrelationRule(
        id="possible_bruteforce_compromise",
        title="Nieudane logowania zakończone udanym logowaniem",
        description=(
            "Co najmniej pięć nieudanych logowań, następnie sukces tej samej tożsamości "
            "na tym samym hoście i z tego samego IP w 10 minut."
        ),
        severity="high",
        mitre=["T1110", "T1078"],
        false_positive_guidance=GUIDANCE,
        pattern=Pattern(
            kind="sequence",
            window_seconds=600,
            group_by=["same_user", "same_host", "same_ip"],
            stages=[
                Stage(name="failed_logins", count=5, condition=AUTH_FAILURE),
                Stage(name="successful_login", count=1, condition=AUTH_SUCCESS),
            ],
        ),
    ),
    CorrelationRule(
        id="repeated_authentication_failures",
        title="Seria nieudanych logowań",
        description=(
            "Pięć nieudanych logowań tej samej tożsamości na tym samym hoście "
            "i z tego samego IP w 5 minut."
        ),
        severity="medium",
        mitre=["T1110"],
        false_positive_guidance=GUIDANCE,
        pattern=Pattern(
            kind="threshold",
            window_seconds=300,
            group_by=["same_user", "same_host", "same_ip"],
            stages=[Stage(name="failed_logins", count=5, condition=AUTH_FAILURE)],
        ),
    ),
    CorrelationRule(
        id="powershell_then_outbound",
        title="PowerShell i późniejsze połączenie wychodzące",
        description=(
            "Uruchomienie PowerShell, następnie połączenie sieciowe tego samego stabilnego "
            "process.entity_id na tym samym hoście w 5 minut."
        ),
        severity="high",
        mitre=["T1059.001"],
        false_positive_guidance=GUIDANCE,
        pattern=Pattern(
            kind="sequence",
            window_seconds=300,
            group_by=["same_host", "same_process"],
            stages=[
                Stage(name="powershell_started", count=1, condition=POWERSHELL),
                Stage(name="outbound_connection", count=1, condition=OUTBOUND),
            ],
        ),
    ),
    CorrelationRule(
        id="login_then_local_admin_change",
        title="Udane logowanie i zmiana lokalnej grupy administratorów",
        description=(
            "Udane logowanie, potem zaobserwowane dodanie członka do grupy S-1-5-32-544 "
            "przez tę samą tożsamość na tym samym hoście w 10 minut."
        ),
        severity="high",
        mitre=["T1078", "T1098.007"],
        false_positive_guidance=GUIDANCE,
        pattern=Pattern(
            kind="sequence",
            window_seconds=600,
            group_by=["same_user", "same_host"],
            stages=[
                Stage(name="successful_login", count=1, condition=AUTH_SUCCESS),
                Stage(name="administrator_group_change", count=1, condition=ADMIN_ADDED),
            ],
        ),
    ),
    CorrelationRule(
        id="possible_multi_stage_compromise",
        title="Potencjalny ciąg przejęcia konta i aktywności na hoście",
        description=(
            "Pięć porażek logowania, sukces, PowerShell, dodanie członka grupy administratorów "
            "i połączenie wychodzące tej samej tożsamości na tym samym hoście w 30 minut. "
            "Proces PowerShell i połączenie wymagają wspólnego stabilnego process.entity_id. "
            "Kolejność czasowa nie dowodzi związku przyczynowego."
        ),
        severity="critical",
        mitre=["T1110", "T1078", "T1059.001", "T1098.007"],
        false_positive_guidance=GUIDANCE,
        pattern=Pattern(
            kind="sequence",
            window_seconds=1800,
            group_by=["same_user", "same_host"],
            stages=[
                Stage(name="failed_logins", count=5, condition=AUTH_FAILURE),
                Stage(name="successful_login", count=1, condition=AUTH_SUCCESS),
                Stage(name="powershell_started", count=1, condition=POWERSHELL),
                Stage(name="administrator_group_change", count=1, condition=ADMIN_ADDED),
                Stage(name="outbound_connection", count=1, condition=OUTBOUND),
            ],
        ),
    ),
)


def rule_definition(rule_id: str) -> CorrelationRule:
    for rule in BUILTIN_RULES:
        if rule.id == rule_id:
            return rule
    raise ApiError(404, "rule_not_found", "Rule not found")
