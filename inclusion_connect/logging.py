import logging
from functools import partial

from django.db import transaction
from pythonjsonlogger.json import JsonFormatter

from inclusion_connect.utils.oidc import oidc_params


def log(logger_name, request, next_url=None, **kwargs):
    logger = logging.getLogger(logger_name)
    data = {"ip_address": request.META["REMOTE_ADDR"]} | kwargs
    params = oidc_params(request, next_url)
    try:
        data["application"] = params["client_id"]
    except KeyError:
        pass
    # sort keys to make testing easier
    transaction.on_commit(partial(logger.info, dict(sorted(data.items()))))


class JsonFormatter(JsonFormatter):
    def parse(self):
        # Remove the empty key "message".
        return []

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        for record_attr in ["name", "levelname"]:
            log_record[record_attr] = getattr(record, record_attr)
