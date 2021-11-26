from datetime import datetime, timedelta
from django.contrib.auth.models import User
from django.db import models


class Species(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    species_name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.species_name


class Token(models.Model):
    id = models.AutoField(default=0, unique=True, primary_key=True, editable=False)
    token = models.CharField(max_length=250, unique=True)
    created_at = models.DateTimeField(default=datetime.now)
    expires_at = models.DateTimeField(default=datetime.now() + timedelta(days=14))

    is_active = models.BooleanField(default=True)

    def expires(self):
        if datetime.now() > self.expires_at:
            self.is_active = False


class UserToken(models.Model):
    id = models.AutoField(default=0, unique=True, primary_key=True, editable=False)
    user_id = models.OneToOneField(User, on_delete=models.CASCADE)
    token_id = models.OneToOneField(Token, on_delete=models.CASCADE)


PERMISSION_CHOICES = [
    ['AD', 'Admin'],
    ['VE', 'Vet'],
    ['RC', 'Receptionist'],
    ['OW', 'Pet owner'],
]


class UserTypeEnum(object):
    ADMIN = 'AD'
    VET = 'VE'
    RECEPTIONIST = 'RC'
    PET_OWNER = 'OW'


class Permission(models.Model):
    id = models.AutoField(default=0, unique=True, primary_key=True, editable=False)
    permission_name = models.CharField(max_length=30, choices=PERMISSION_CHOICES, default=UserTypeEnum.PET_OWNER)

# todo:   class pet, owner, pet_owner
# class Zwierze(models.Model):
#     id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True, editable=False)
#     nazwa = models.CharField(max_length=200)
#     gatunek = models.ForeignKey(Gatunek, on_delete=models.CASCADE)
#     data_urodzenia = models.DateTimeField(auto_now_add=True)
#     dodatkowe_informacje = models.TextField(null=True, blank=True)
