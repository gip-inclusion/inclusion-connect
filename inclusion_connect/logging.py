from pythonjsonlogger.json import JsonFormatter

from inclusion_connect.utils.oidc import oidc_params


def log_data(request, next_url=None):
    log_data = {"ip_address": request.META["REMOTE_ADDR"]}
    params = oidc_params(request, next_url)
    try:
        log_data["application"] = params["client_id"]
    except KeyError:
        pass
    return log_data


class JsonFormatter(JsonFormatter):
    def parse(self):
        # Remove the empty key "message".
        return []

    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        for record_attr in ["name", "levelname"]:
            log_record[record_attr] = getattr(record, record_attr)
