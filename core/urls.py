from django.contrib import admin
from django.urls import path, include
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
urlpatterns = [
    path("admin/", admin.site.urls),
    path("api/", include("api_urls.authentic_urls")),
    path("api/", include("api_urls.base_urls")),

    # path("api/", include("api.base_urls")),
]
