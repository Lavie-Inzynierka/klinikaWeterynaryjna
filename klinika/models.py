from datetime import datetime, timedelta
from django.db import models
import enum


class UserTypeEnum(enum.Enum):
    ADMIN = 'AD'
    VET = 'VE'
    RECEPTIONIST = 'RC'
    PET_OWNER = 'OW'


Gender_choices = (
    ('Female', 'f'),
    ('Male', 'm'),
)


class MyUser(models.Model):
    id = models.AutoField( unique=True, primary_key=True, editable=False)
    username = models.CharField(max_length=30, unique=True)
    first_name = models.CharField(max_length=32)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20, null=True)
    email = models.EmailField(max_length=60, unique=True)
    password = models.TextField(null=False)
    is_active = models.BooleanField(default=False)
    note = models.TextField(null=True)

    def __str__(self):
        return self.username


class Species(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    species_name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.species_name


class Token(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    token = models.CharField(max_length=250, unique=True)
    created_at = models.DateTimeField(default=datetime.now)
    expires_at = models.DateTimeField(default=datetime.now() + timedelta(days=14))
    user = models.ForeignKey(MyUser, on_delete=models.CASCADE)

    is_active = models.BooleanField(default=True)

    def expires(self):
        if datetime.now() > self.expires_at:
            self.is_active = False

#
# todo:   class pet with foreign key user with OW
# class Zwierze(models.Model):
#     id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True, editable=False)
#     nazwa = models.CharField(max_length=200)
#     gatunek = models.ForeignKey(Gatunek, on_delete=models.CASCADE)
#     data_urodzenia = models.DateTimeField(auto_now_add=True)
#     dodatkowe_informacje = models.TextField(null=True, blank=True)
