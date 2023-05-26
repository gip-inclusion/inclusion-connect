import pytest
from django.core.exceptions import ValidationError

from inclusion_connect.utils.password_validation import CnilCompositionPasswordValidator
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


class TestCnilCompositionPasswordValidator:
    @pytest.mark.parametrize(
        "testinput_expected",
        [
            ("foo", "Le mot de passe ne contient pas assez de caractères."),
            (
                "123abc-|-|-|",
                "Le mot de passe doit contenir des majuscules, minuscules, chiffres et des caractères spéciaux.",
            ),
            ("123aBc-|-|-|", None),
            ("(123abc)(ABC)", None),
            (
                "13digits+spec",
                "Le mot de passe doit contenir des majuscules, minuscules, chiffres et des caractères spéciaux.",
            ),
            ("14digits+speci", None),
            ("14DiGiTs+speci", None),
            (
                "only-long-password",
                "Le mot de passe doit contenir des majuscules, minuscules, chiffres et des caractères spéciaux.",
            ),
        ],
    )
    def test_validator(self, testinput_expected):
        pw, expected = testinput_expected
        validator = CnilCompositionPasswordValidator()
        if expected is None:
            validator.validate(pw)
        else:
            with pytest.raises(ValidationError) as excinfo:
                validator.validate(pw)
                assert excinfo.args == [expected]
