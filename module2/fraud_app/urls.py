from django.urls import path
from . import views
urlpatterns = [
    path("", views.home, name="home"),
    path("scan/", views.scan, name="scan"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("history/", views.history, name="history"),
    path("history/case/<str:case_id>/", views.case_detail, name="case_detail"),
    path("api/quick-scan/", views.QuickScanAPI.as_view(), name="quick_scan"),
]
