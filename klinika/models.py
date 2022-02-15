from datetime import datetime, timedelta
from django.db import models
import enum
from django.core.validators import MinLengthValidator


class UserTypeEnum(enum.Enum):
    ADMIN = 'AD'
    VET = 'VE'
    RECEPTIONIST = 'RC'
    PET_OWNER = 'OW'


Gender_choices = (
    ('Samica', 'f'),
    ('Samiec', 'm'),
)

Status_choices = (
    ('Zaplanowana', 'z'),
    ('Odbyta', 'o'),
    ('Anulowana', 'a'),
)

Dose_choices = (
    ('mg', 'mg'),
    ('mg/g', 'mg/g'),
    ('mg/ml', 'mg/ml'),
    ('ml', 'ml'),
)

Quantity_choices = (
    ('sz.', 'sz'),
    ('mg', 'mg'),
    ('ml', 'ml'),
    ('op', 'op'),
    ('lst', 'lst')
)


class MyUser(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
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


class UserType(models.Model):
    user = models.ForeignKey(MyUser, on_delete=models.PROTECT)
    user_type = models.CharField(max_length=12)

    def type_check(self):
        if not UserTypeEnum.__members__.keys().__contains__(self.user_type):
            raise ValueError("Wartość nie istnieje!")


class UserAddresses(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    address = models.CharField(max_length=250, null=True)
    user = models.ForeignKey(MyUser, on_delete=models.PROTECT)
    current = models.BooleanField(default=False)

    def __str__(self):
        return self.address


class Species(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    species_name = models.CharField(max_length=255, unique=True)
    additional_information = models.TextField(null=True)

    def __str__(self):
        return self.species_name


class Token(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    token = models.CharField(max_length=250, unique=True)
    created_at = models.DateTimeField(default=datetime.now)
    expires_at = models.DateTimeField(default=datetime.now() + timedelta(days=14))
    user = models.ForeignKey(MyUser, on_delete=models.PROTECT)

    is_active = models.BooleanField(default=True)

    def expires(self):
        if self.created_at + timedelta(days=14) > self.expires_at:
            self.is_active = False


class Owner(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    first_name = models.CharField(max_length=32)
    last_name = models.CharField(max_length=100)
    phone_number = models.CharField(max_length=20, null=True)
    email = models.EmailField(max_length=60)
    user = models.ForeignKey(MyUser, null=True, on_delete=models.PROTECT)


class Pet(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    name = models.CharField(max_length=32)
    date_of_birth = models.DateTimeField()
    sex = models.CharField(max_length=6, choices=Gender_choices)
    species = models.ForeignKey(Species, on_delete=models.PROTECT)
    owner = models.ForeignKey(Owner, on_delete=models.PROTECT)
    additional_information = models.TextField(null=True)


class Visit(models.Model):
    id = models.AutoField(unique=True, primary_key=True, editable=False)
    visit_date = models.DateField()
    visit_planned = models.DateTimeField()
    visit_time = models.TimeField()
    status = models.CharField(max_length=11, choices=Status_choices)
    pet = models.ForeignKey(Pet, null=True, on_delete=models.PROTECT)
    vet = models.ForeignKey(MyUser, on_delete=models.PROTECT)
    note = models.TextField(null=True)
