import logging.handlers
import threading

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from pythonjsonlogger import jsonlogger

from inclusion_connect.utils.oidc import oidc_params


def log_data(request, next_url=None):
    log_data = {"ip_address": request.META["REMOTE_ADDR"]}
    params = oidc_params(request, next_url)
    try:
        log_data["application"] = params["client_id"]
    except KeyError:
        pass
    return log_data


class JsonFormatter(jsonlogger.JsonFormatter):
    def parse(self):
        # Remove the empty key "message".
        return []

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        for record_attr in ["name", "levelname"]:
            log_record[record_attr] = getattr(record, record_attr)


class ElasticSearchHandler(logging.handlers.BufferingHandler):
    timer = None

    def __init__(  # noqa: PLR0913 Too many arguments to function call.
        self,
        *,
        capacity,
        send_after_inactive_for_secs=2.0,
        host,
        index_name,
        es_timeout_secs=5,
    ):
        """
        Inspired from https://github.com/cmanaha/python-elasticsearch-logger/blob/master/cmreslogging/handlers.py.

        :param int capacity: Max number of log records before sending to ElasticSearch.
        :param float send_after_inactive_for_secs: Send to ElasticSearch if no records
            are emitted in send_after_inactive_for_secs seconds.
        """
        super().__init__(capacity)
        self.send_after_inactive_for_secs = send_after_inactive_for_secs
        self.es_client = Elasticsearch(host, http_compress=True, request_timeout=es_timeout_secs, max_retries=10)
        self.index_name = index_name

    def emit(self, record):
        if self.timer and self.timer.is_alive():
            self.timer.cancel()
        formatted_record = self.format(record)
        super().emit(formatted_record)
        self.timer = threading.Timer(self.send_after_inactive_for_secs, self.flush)
        self.timer.start()

    def send_to_elastic(self, log_buffer):
        actions = ({"_source": log} for log in log_buffer)
        bulk(client=self.es_client, actions=actions, index=self.index_name, stats_only=True)

    def flush(self):
        with self.lock:
            log_buffer = self.buffer
            self.buffer = []
        if log_buffer:
            t = threading.Thread(target=self.send_to_elastic, args=(log_buffer,), daemon=False)
            t.start()
