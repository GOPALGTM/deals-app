from django.shortcuts import render
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import status
from apps.users.models import CustomUser
from apps.registration.serializer import (RegisterSerializer,
                                          ChangePasswordSerializer,
                                          LoginSerializer,
                                          ForgotPasswordSerializer,
                                          ResetPasswordSerializer)
from rest_framework.exceptions import ValidationError as DRFValidationError
from django.contrib.auth import authenticate
# from apps.api.permissions import IsAuthenticatedOrHasUserAPIKey
from apps.registration.utils.exception import get_first_exception_message
from rest_framework import serializers
from apps.registration.utils.email import (send_verification_email,
                                           send_otp_for_forgot_password_email,
                                           send_reset_password_email_confimation,
                                           reset_password,
                                           send_welcome_email)
from apps.registration.utils.otp import generate_otp
from apps.registration.models.otp import TOTP
from django.db.models import Q
from datetime import datetime

# Create your views here.

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {"refresh": str(refresh), "access_token": str(refresh.access_token)}


class RegisterView(APIView):
    """
    Username, Email, Password,confirm_password
    """
    queryset = None
    permission_classes = (AllowAny,)
    serializer_class = RegisterSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        
        try:       
            if serializer.is_valid(raise_exception=True):
                validated_data = serializer.validated_data
                if validated_data.get('password') != validated_data.get('confirm_password'):
                    raise serializers.ValidationError('Password and confirm password do not match')
                serializer.save()
                send_verification_email(serializer.validated_data.get("email"))
                return Response(
                    {
                        "message": "Your account has been registered successfully, please check your email for further instructions.",
                    },
                    status=status.HTTP_201_CREATED,
                )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LoginView(APIView):
    """
    Client Login API

    Required fields are:
    
    Valid client credentials

    """
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid():
                username_or_email = serializer.data.get("username_or_email")
                password = serializer.data.get("password")
                user = authenticate(
                    username=username_or_email, password=password
                ) or authenticate(email=username_or_email, password=password)
                
                if user is not None and user.is_active:
                    token = get_tokens_for_user(user)
                    return Response(
                        {
                            "token": token,
                            "profile": {
                                "username": user.username,
                                "email": user.email
                            },
                            "message": "Login successful.",
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    return Response(
                        {"message": "Invalid credentials."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
            
            #     else:
            #         return Response(
            #             {"message": "Invalid credentials."},
            #             status=status.HTTP_400_BAD_REQUEST,
            #         )
            # else:
            #     return Response(
            #         {"message": "Bad Request."},
            #         status=status.HTTP_400_BAD_REQUEST,
            #     )
        except DRFValidationError as e:
            return Response(
                {"message": get_first_exception_message(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)

class ChangePasswordView(APIView):
    """
    Change Password API

    Required correct old password
    
    """
    queryset = None
    # permission_classes = (IsAuthenticatedOrHasUserAPIKey,)r
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        try:
            serializer = self.serializer_class(data=request.data)
            if serializer.is_valid(raise_exception=True):
                if not self.request.user.check_password(
                    serializer.data.get("old_password")
                ):
                    return Response(
                        {"message": "Invalid current password."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                # set_password also hashes the password that the user will get
                self.request.user.set_password(serializer.data.get("new_password"))
                self.request.user.save()
                return Response(
                    {"message": "Password has been changed."},
                    status=status.HTTP_200_OK,
                )
            return Response(
                {"message": "Bad Request."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except DRFValidationError as e:
            return Response(
                {"message": get_first_exception_message(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


# @extend_schema(
#     tags=["Users"],
#     responses={
#         status.HTTP_200_OK: inline_serializer(
#             name="verify_account_successful",
#             fields={
#                 "message": serializers.CharField(
#                     default="Congratulations! Account has been verified."
#                 ),
#             },
#         ),
#         status.HTTP_401_UNAUTHORIZED: inline_serializer(
#             name="verify_account_failure_invalid_otp",
#             fields={
#                 "message": serializers.CharField(default="Invalid OTP."),
#             },
#         ),
#         status.HTTP_400_BAD_REQUEST: inline_serializer(
#             name="verify_account_bad_request",
#             fields={
#                 "message": serializers.CharField(default="Verification failed."),
#             },
#         ),
#     },
# )


class ForgotPasswordView(APIView):
    """
    Forgot password API

    Required fields are:
    
    Registered username or email

    """
    queryset = None
    permission_classes = (AllowAny,)
    serializer_class = ForgotPasswordSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        try:
            if serializer.is_valid(raise_exception=True):
                username_or_email = request.data.get("username_or_email")
                user = CustomUser.objects.filter(
                    Q(username=username_or_email) | Q(email=username_or_email)
                ).first()

                if user:
                    totp = TOTP.objects.create(
                        user=user,
                        otp=generate_otp(),
                        otp_type=TOTP.PROCESS.FORGET_PASSWORD,
                    )
                    send_otp_for_forgot_password_email(user.email, totp.otp)
                    return Response(
                        {
                            "message": "Reset password instructions has been sent to registed email address.",
                        },
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    return Response(
                        {
                            "message": "Invalid email or username.",
                        },
                        status=status.HTTP_400_BAD_REQUEST,
                    )

            else:
                return Response(
                    {
                        "message": "Invalid email or username.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

        except DRFValidationError as e:
            return Response(
                {"message": get_first_exception_message(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ResetPasswordView(APIView):
    """
    Reset password API
    
    Required fields are:

    username or email, valid otp, new password

    """
    queryset = None
    permission_classes = (AllowAny,)
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        username_or_email = request.data.get("username_or_email")
        otp = request.data.get("otp")
        new_password = request.data.get("new_password")
        try:
            if serializer.is_valid(raise_exception=True):

                user = CustomUser.objects.filter(
                    Q(username=username_or_email) | Q(email=username_or_email)
                ).first()
                totp = TOTP.objects.filter(
                    user=user, otp=otp, otp_type=TOTP.PROCESS.FORGET_PASSWORD
                ).first()
                if totp is not None and totp.expiry > datetime.datetime.now():
                    user.set_password(new_password)
                    user.save()
                    totp.delete()
                    send_reset_password_email_confimation(user.email)
                    return Response(
                        {"message": "Password reset successful."},
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    return Response(
                        {"message": "Invalid OTP or OTP has been Expired."},
                        status=status.HTTP_400_BAD_REQUEST,
                    )

        except DRFValidationError as e:
            return Response(
                {"message": get_first_exception_message(e)},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except Exception as e:
            return Response({"message": str(e)}, status=status.HTTP_400_BAD_REQUEST)
