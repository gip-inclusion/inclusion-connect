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
