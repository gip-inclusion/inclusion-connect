from django.urls import re_path

from inclusion_connect.self_service import views


app_name = "self_service"

urlpatterns = [
    # Application management views
    re_path(r"^applications/$", views.ApplicationList.as_view(), name="list"),
    re_path(r"^applications/register/$", views.ApplicationRegistration.as_view(), name="register"),
    re_path(r"^applications/(?P<pk>[\w-]+)/$", views.ApplicationDetail.as_view(), name="detail"),
    re_path(r"^applications/(?P<pk>[\w-]+)/delete/$", views.ApplicationDelete.as_view(), name="delete"),
    re_path(r"^applications/(?P<pk>[\w-]+)/update/$", views.ApplicationUpdate.as_view(), name="update"),
]
