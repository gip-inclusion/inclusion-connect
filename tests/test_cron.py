import json
from typing import NamedTuple

from django.conf import settings


class CronDefinition(NamedTuple):
    schedule: str
    command: str


def normalize_cron_definition(definition):
    minute, hour, day_of_month, month, day_of_week, *cmd = definition.split()
    _launcher, *cmd = cmd
    return CronDefinition(f"{minute} {hour} {day_of_month} {month} {day_of_week}", " ".join(cmd))


def test_clevercloud_and_scalingo_definition_match():
    root = settings.BASE_DIR.parent
    clever_path = root / "clevercloud" / "cron.json"
    scalingo_path = root / "cron.json"
    clever_crons = json.loads(clever_path.read_bytes())
    scalingo_crons = json.loads(scalingo_path.read_bytes())
    assert len(clever_crons) == len(scalingo_crons["jobs"])
    clever_cmds = sorted([normalize_cron_definition(entry) for entry in clever_crons])
    scalingo_cmds = sorted([normalize_cron_definition(entry["command"]) for entry in scalingo_crons["jobs"]])
    assert clever_cmds == scalingo_cmds
