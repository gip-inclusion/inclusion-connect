from django.contrib.admin import sites as admin_sites


class AdminSite(admin_sites.AdminSite):
    site_header = "Administration Inclusion Connect"
    site_title = "Administration Inclusion Connect"
    index_title = None
