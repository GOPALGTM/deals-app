from django.core.mail import send_mail
from django.conf import settings


def send_verification_email(user_email):
    send_mail(
        subject=("Welcome to your {} Account!").format("deals"),
        message="verify your account",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False      
    )


def send_otp_for_forgot_password_email(user_email, otp):

    send_mail(
        subject=("Did you forgot your {} Account password?").format('deals'),
        message=f"otp is {otp}",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False
    )


def send_reset_password_email_confimation(user_email):
    send_mail(
        subject=("Password reset successful | {} Account!").format('deals'),
        message="Your {} Account password has been updated successfully.".format('PLV2'),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user_email],
        fail_silently=False
    )

        
def send_welcome_email(user):
    send_mail(
        subject=("Activate your {} Account!").format('deals'),
        message="Welcome to cert python",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False
    )


def reset_password(user):
    send_mail(
        subject=("Reset your password {} Account!").format('deals'),
        message="Reset your passwod",
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[user.email],
        fail_silently=False,
        # html_message=
    )
        # html_message=render_to_string("account/email/reset_password_email_confimation.html"),
    