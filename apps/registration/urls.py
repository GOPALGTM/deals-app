from django.urls import path
from apps.registration import views

urlpatterns = [
    path('user/register/', views.RegisterView.as_view(), name='auth_register'),
    # path('user/verify-account/', UserViews.VerifyAccountView.as_view(), name='verify_account'),
    path('user/login/', views.LoginView.as_view(), name='user_login'),
    path('user/change-password/',views.ChangePasswordView.as_view(), name='change_password'),
    path('user/forgot-password/', views.ForgotPasswordView.as_view(), name='forgot_password'),
    path('user/reset-password/', views.ResetPasswordView.as_view(), name='reset_password'),
]