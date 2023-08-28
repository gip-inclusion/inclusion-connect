from typing import List, NamedTuple

from django.contrib.messages import DEFAULT_LEVELS, get_messages
from django.http import HttpResponse


class Message(NamedTuple):
    level: int
    message: str


LEVEL_TO_NAME = {intlevel: name for name, intlevel in DEFAULT_LEVELS.items()}


def assertMessages(response: HttpResponse, expected_messages: List[Message]):
    request_messages = get_messages(response.wsgi_request)
    for message, (expected_level, expected_msg) in zip(request_messages, expected_messages, strict=True):
        msg_levelname = LEVEL_TO_NAME.get(message.level, message.level)
        expected_levelname = LEVEL_TO_NAME.get(expected_level, expected_level)
        assert (msg_levelname, message.message) == (expected_levelname, expected_msg)


def assertRecords(caplog, logs):
    assert caplog.record_tuples == [
        (
            log[0],
            log[1],
            str({"ip_address": "127.0.0.1"} | log[2]) if isinstance(log[2], dict) else log[2],
        )
        for log in logs
    ]
    caplog.clear()
