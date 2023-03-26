# from apps.lms.models import TOTP
# from apps.mapi.utils.email import send_otp_verification_email
# from apps.mapi.utils.otp import generate_otp
from apps.users.models import CustomUser
from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework.validators import UniqueValidator

class LoginSerializer(serializers.ModelSerializer):
    username_or_email = serializers.CharField(max_length=255)
    class Meta:
        model = CustomUser
        fields = ["username_or_email","password"]


class RegisterSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=CustomUser.objects.all(),
                message="Username already registered",
            ),
        ],
    )

    email = serializers.EmailField(
        required=True,
        validators=[
            UniqueValidator(
                queryset=CustomUser.objects.all(),
                message="Email address already registered",
            ),
        ],
    )

    password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )

    confirm_password = serializers.CharField(
        write_only=True, required=True, validators=[validate_password]
    )

    class Meta:
        model = CustomUser
        fields = (
            "username",
            "email",
            "password",
            "confirm_password",
        )
    
    def create(self, validated_data):
    # Remove the confirm_password field from the validated_data dictionary
        confirm_password = validated_data.pop('confirm_password', None)
        # Create and return the CustomUser instance
        user = CustomUser.objects.create_user(**validated_data)
        return user

class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint.
    """

    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, validators=[validate_password])


class ForgotPasswordSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(
        max_length=255,
        required=True,
        error_messages={"required": "Usename/Email is required"},
    )


# class ResendOTPSerializer(serializers.Serializer):
#     username_or_email = serializers.CharField(
#         max_length=255,
#         required=True,
#         error_messages={"required": "Usename/Email is required"},
#     )
#     otp_type = serializers.ChoiceField(
#         choices=TOTP.PROCESS_TYPES,
#         required=True,
#         error_messages={"required": "OTP Type is required"},
#     )


class ResetPasswordSerializer(serializers.Serializer):
    username_or_email = serializers.CharField(
        max_length=255,
        required=True,
        error_messages={"required": "Usename/Email is required"},
    )
    otp = serializers.CharField(
        required=True, error_messages={"required": "OTP is required"}
    )
    new_password = serializers.CharField(
        required=True,
        validators=[validate_password],
        error_messages={"required": "New Password is required"},
    )

    class Meta:
        fields = ["username_or_email", "otp", "new_password"]