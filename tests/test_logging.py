import logging
from unittest import mock

from freezegun import freeze_time

from inclusion_connect.logging import ElasticSearchHandler


@freeze_time("2023-05-05 11:11:11")
def test_log_formatting(snapshot):
    logger = logging.getLogger("inclusion_connect")  # Root logger for IC.
    [handler] = logger.handlers
    logger.info({"key": "value", "other_key": "value"})
    stream = handler.stream
    stream.seek(0)
    assert stream.read() == snapshot(name="log serialized as JSON with metadata")


@mock.patch("inclusion_connect.logging.bulk")
class TestElasticSearchHandler:
    def test_elastic_search_handler_sends_at_capacity(self, bulk_mock):
        handler = ElasticSearchHandler(capacity=1, index_name="test", host="https://localhost:9200")
        handler.handle(logging.LogRecord("test_logger", logging.INFO, "pathname", 1, "msg", (), None))
        bulk_mock.assert_called_once()
        handler.timer.cancel()

    def test_elastic_search_handler_after_some_time(self, bulk_mock):
        handler = ElasticSearchHandler(
            capacity=100,
            index_name="test",
            host="https://localhost:9200",
            send_after_inactive_for_secs=0,
        )
        handler.handle(logging.LogRecord("test_logger", logging.INFO, "pathname", 1, "msg", (), None))

        # This might be a bit fragile: the timer thread may execute before the next assertion.
        # That’s unlikely, considering the amount of work the timer thread has compared to the test thread,
        # and thousands runs do not show flakiness.
        # Keeping the assertion makes the test easier to follow and more robust.
        bulk_mock.assert_not_called()

        timer_internal_event = handler.timer.finished
        # Wait for the timer thread to complete, and verify wait did not timeout.
        assert timer_internal_event.wait(1) is True
        bulk_mock.assert_called_once()
