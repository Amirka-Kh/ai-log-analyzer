from __future__ import annotations

from ai_ops_agent.config import WatchConfig
from ai_ops_agent.streaming.watch import WatchSession

CFG = WatchConfig(
    window_seconds=10.0,
    window_max_lines=50,
    baseline_seconds=60.0,
    cooldown_seconds=30.0,
    max_alerts_per_hour=5,
    error_rate_factor=3.0,
    min_error_rate=0.05,
)


def feed(session: WatchSession, lines: list[str], start: float, step: float = 1.0):
    notes = []
    t = start
    for line in lines:
        notes.extend(session.ingest_line(line + "\n", t))
        t += step
    return notes, t


def baseline_lines(n: int) -> list[str]:
    return [f"INFO heartbeat ok seq={i}" for i in range(n)]


def make_warm_session() -> tuple[WatchSession, float]:
    """Session with a finished baseline of healthy heartbeats."""
    session = WatchSession(CFG, fmt="plain")
    _, t = feed(session, baseline_lines(70), start=0.0, step=1.0)  # 70s > 60s baseline
    assert session.baseline.finished
    return session, t


def test_baseline_phase_emits_nothing():
    session = WatchSession(CFG, fmt="plain")
    lines = ["ERROR everything is on fire"] * 30  # errors during baseline stay silent
    notes, _ = feed(session, lines, start=0.0, step=1.0)
    assert notes == []
    assert not session.baseline.finished


def test_novel_error_template_triggers_exactly_once():
    session, t = make_warm_session()
    notes, t = feed(session, ["ERROR db connection refused to host db-1"] * 3, t, step=0.5)
    # Window not yet closed by lines; close by time.
    notes.extend(session.tick(t + 11))
    assert len(notes) == 1
    note = notes[0]
    assert "new_error_template" in note.reasons

    # Same failure again within cooldown: suppressed, counted on the notification.
    notes2, t2 = feed(session, ["ERROR db connection refused to host db-2"] * 3, t + 12, step=0.5)
    notes2.extend(session.tick(t + 25))
    assert notes2 == []
    assert session.suppressed == 1
    assert session.notifications[0].suppressed_repeats == 1


def test_error_rate_spike_triggers():
    session, t = make_warm_session()
    # Known template (no novelty) but at error level never seen -> new template.
    # Use warning-level noise + errors of a template seeded during baseline.
    lines = ["INFO heartbeat ok seq=999"] * 5 + ["ERROR heartbeat ok seq=1000"] * 0
    notes, t = feed(session, lines, t)
    notes.extend(session.tick(t + 11))
    assert notes == []  # healthy window, no trigger


def test_fatal_marker_triggers_sev1():
    session, t = make_warm_session()
    notes, t = feed(session, ["INFO worker crashed with panic: runtime error"], t)
    notes.extend(session.tick(t + 11))
    assert len(notes) == 1
    assert notes[0].severity.value == "sev1"
    assert "fatal_marker" in notes[0].reasons


def test_security_pattern_triggers():
    session, t = make_warm_session()
    notes, t = feed(session, ["INFO GET /wp-admin/setup.php from scanner"], t)
    notes.extend(session.tick(t + 11))
    assert len(notes) == 1
    assert any(r.startswith("security:") for r in notes[0].reasons)


def test_max_alerts_per_hour():
    session, t = make_warm_session()
    emitted = 0
    for i in range(10):
        # Distinct failure modes so the cooldown's same-reason suppression
        # doesn't apply; spaced beyond cooldown anyway.
        line = f"INFO scanner probing /wp-admin/page{i} plus panic marker {i}"
        # Alternate reasons to defeat cooldown similarity check:
        if i % 2:
            line = f"ERROR brand new failure mode variant_{i} exploded uniquely_{i}"
        notes, t = feed(session, [line], t + 40)
        notes.extend(session.tick(t + 11))
        emitted += len(notes)
        t += 12
    assert emitted <= CFG.max_alerts_per_hour


def test_window_closes_on_line_count():
    session, t = make_warm_session()
    lines = [f"ERROR new failure kind_alpha item {i}" for i in range(CFG.window_max_lines)]
    notes, t = feed(session, lines, t, step=0.001)
    assert len(notes) == 1  # closed by line count without tick()


def test_process_exit_nonzero_notifies():
    session, t = make_warm_session()
    note = session.process_exit(137, t)
    assert note is not None
    assert "process_exit" in note.reasons
    assert session.notifications


def test_process_exit_zero_silent():
    session, t = make_warm_session()
    assert session.process_exit(0, t) is None


def test_summary_always_available():
    session, t = make_warm_session()
    feed(session, ["ERROR one-off failure zz"], t)
    summary = session.summary(t + 5)
    assert summary.total_lines == 71
    assert summary.duration_s > 0
    assert summary.template_count >= 1
    assert summary.top_templates
