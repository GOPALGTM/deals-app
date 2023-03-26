from django.db import models
from apps.users.models import CustomUser
from datetime import timedelta, datetime


class TOTP(models.Model):
    
    class PROCESS():
        VERIFY_MOBILE = "VERIFY_MOBILE"
        VERIFY_EMAIL = "VERIFY_EMAIL"
        LOGIN_OTP = "LOGIN_OTP"
        FORGET_PASSWORD = "FORGET_PASSWORD"

    PROCESS_TYPES = (
        (PROCESS.VERIFY_MOBILE,PROCESS.VERIFY_MOBILE),
        (PROCESS.VERIFY_EMAIL,PROCESS.VERIFY_EMAIL),
        (PROCESS.LOGIN_OTP,PROCESS.LOGIN_OTP),
        (PROCESS.FORGET_PASSWORD,PROCESS.FORGET_PASSWORD),     
    )

    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    otp = models.CharField(max_length=6)
    expiry = models.DateTimeField()
    otp_type = models.CharField(choices=PROCESS_TYPES, max_length=50)


    def save(self, *args, **kwargs):
        current_time=datetime.now()
        self.expiry =  current_time+ timedelta(minutes=30)
        super(TOTP, self).save(*args, **kwargs)



    class Meta:
        verbose_name = ('Time Based OTP')



