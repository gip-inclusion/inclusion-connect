from inclusion_connect.utils.urls import add_url_params, get_url_params


def test_add_url_params():
    """Test `urls.add_url_params()`."""

    base_url = "http://localhost/test?next=/siae/search%3Fdistance%3D100%26city%3Dstrasbourg-67"

    url_test = add_url_params(base_url, {"test": "value"})
    assert url_test == "http://localhost/test?next=%2Fsiae%2Fsearch%3Fdistance%3D100%26city%3Dstrasbourg-67&test=value"

    url_test = add_url_params(base_url, {"mypath": "%2Fvalue%2Fpath"})

    assert url_test == (
        "http://localhost/test?next=%2Fsiae%2Fsearch%3Fdistance%3D100%26city%3Dstrasbourg-67"
        "&mypath=%252Fvalue%252Fpath"
    )

    url_test = add_url_params(base_url, {"mypath": None})

    assert url_test == "http://localhost/test?next=%2Fsiae%2Fsearch%3Fdistance%3D100%26city%3Dstrasbourg-67"

    url_test = add_url_params(base_url, {"mypath": ""})

    assert url_test == "http://localhost/test?next=%2Fsiae%2Fsearch%3Fdistance%3D100%26city%3Dstrasbourg-67&mypath="


def test_get_url_params():
    url = "http://localhost/test?next=/siae/search%3Fdistance%3D100%26city%3Dstrasbourg-67"

    assert get_url_params(url) == {"next": "/siae/search?distance=100&city=strasbourg-67"}
