import logging

from freezegun import freeze_time


@freeze_time("2023-05-05 11:11:11")
def test_log_formatting(snapshot):
    logger = logging.getLogger("inclusion_connect")  # Root logger for IC.
    [handler] = logger.handlers
    logger.info({"key": "value", "other_key": "value"})
    stream = handler.stream
    stream.seek(0)
    assert stream.read() == snapshot(name="log serialized as JSON with metadata")
