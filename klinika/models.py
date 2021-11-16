from django.db import models
import uuid


# Create your models here.

# todo: uuid na int
class Species(models.Model):
    id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True, editable=False)
    species_name = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.species_name
# todo: class pet, owner, pet_owner
# class Zwierze(models.Model):
#     id = models.UUIDField(default=uuid.uuid4, unique=True, primary_key=True, editable=False)
#     nazwa = models.CharField(max_length=200)
#     gatunek = models.ForeignKey(Gatunek, on_delete=models.CASCADE)
#     data_urodzenia = models.DateTimeField(auto_now_add=True)
#     dodatkowe_informacje = models.TextField(null=True, blank=True)
