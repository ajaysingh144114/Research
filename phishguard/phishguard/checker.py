"""Combine the local rule checks with Claude's judgement into one answer."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from . import ai
from .signals import PHISHING_AT, SignalReport, analyze

LEVELS = {"safe": 0, "suspicious": 1, "phishing": 2}


@dataclass
class Result:
    verdict: str  # "safe", "suspicious" or "phishing"
    reasons: list[str]
    advice: str
    rule_score: int
    rule_findings: list[str]
    links: list[str]
    used_ai: bool
    confidence: int | None = None
    attack_type: str | None = None
    message_type: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


RULE_ADVICE = {
    "safe": "No common warning signs found. Still, only open links you were expecting.",
    "suspicious": "Be careful. Do not click links or reply; contact the company through its official app or website instead.",
    "phishing": "Do not click any link, reply, call the number or share any code. Report it (email: 'Report phishing' in your mail app; SMS: forward to 7726 in the US/UK, or use Chakshu on sancharsaathi.gov.in in India), then delete it. If you already lost money in India, call 1930.",
}


def check_message(message: str, *, use_ai: bool = True, client=None, model: str | None = None) -> Result:
    """Check one email or SMS and return a verdict with reasons."""
    message = message.strip()
    if not message:
        raise ValueError("The message is empty. Paste an email or SMS to check.")

    signals: SignalReport = analyze(message)
    rule_reasons = [f.reason for f in signals.findings]

    if use_ai:
        try:
            verdict = ai.classify(message, signals, client=client, model=model)
        except ai.AIUnavailable as e:
            result = _rules_only(signals, rule_reasons)
            result.notes.append(f"AI check skipped: {e} The answer below uses the local rules only.")
            return result
        return _combine(verdict, signals, rule_reasons)

    result = _rules_only(signals, rule_reasons)
    result.notes.append("Offline mode: only the local rules were used.")
    return result


def _rules_only(signals: SignalReport, rule_reasons: list[str]) -> Result:
    return Result(
        verdict=signals.verdict,
        reasons=rule_reasons or ["No common phishing warning signs were found."],
        advice=(
            "Only minor warning signs found. Still, only open links you were expecting."
            if signals.verdict == "safe" and rule_reasons
            else RULE_ADVICE[signals.verdict]
        ),
        rule_score=signals.score,
        rule_findings=rule_reasons,
        links=signals.urls,
        used_ai=False,
    )


def _combine(verdict: ai.AIVerdict, signals: SignalReport, rule_reasons: list[str]) -> Result:
    final = verdict.verdict
    notes: list[str] = []

    # Never let the AI wave through a message the rules find clearly dangerous.
    # This also limits the damage if a message manages to trick the model.
    if signals.score >= PHISHING_AT and LEVELS[final] < LEVELS["suspicious"]:
        final = "suspicious"
        notes.append("Claude said safe, but the local rules found strong warning signs, so the result was raised to suspicious.")

    return Result(
        verdict=final,
        reasons=verdict.reasons,
        advice=verdict.advice if final == verdict.verdict else RULE_ADVICE[final],
        rule_score=signals.score,
        rule_findings=rule_reasons,
        links=signals.urls,
        used_ai=True,
        confidence=verdict.confidence,
        attack_type=verdict.attack_type,
        message_type=verdict.message_type,
        notes=notes,
    )
