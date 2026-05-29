from django import template
from django.templatetags.static import static


register = template.Library()

URL_THEME = "vendor/theme-inclusion/"


@register.simple_tag
def static_theme_images(url_path):
    """
    Usage:
        {% load theme_inclusion %}
        {% static_theme_images url_path %}
    """
    return static(f"{URL_THEME}images/{url_path}")
