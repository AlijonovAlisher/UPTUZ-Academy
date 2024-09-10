from django.urls import path
from api_views.base_views import (
    PupilListCreateView,
    PupilRetrieveUpdateDestroyView,
    LoginView,
    ChangeEmailView,
    ChangeUsernameView,
    RequestPasswordResetEmail,
    SetNewPasswordAPIView,


)
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView



urlpatterns = [
    # Pupil registration and management
    path('pupils/register/', PupilListCreateView.as_view(), name='pupil-list-create'),
    path('pupils/register/<uuid:pk>/', PupilRetrieveUpdateDestroyView.as_view(), name='pupil-detail'),

    # Custom login view
    path('pupils/login/', LoginView.as_view(), name='login'),

    # JWT token operations
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(), name='token_verify'),

    # User management operations
    path('pupils/change-password/', RequestPasswordResetEmail.as_view(), name='change-password'),
    path('pupils/change-email/', ChangeEmailView.as_view(), name='change-email'),
    path('pupils/change-username/', ChangeUsernameView.as_view(), name='change-username'),

    path('password-reset-confirm/', SetNewPasswordAPIView.as_view(), name='set_new_password'),

    path('password-reset-confirm/<uidb64>/<token>/', SetNewPasswordAPIView.as_view(), name='password-reset-confirm'),
]
