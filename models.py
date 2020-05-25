from tkinter import CASCADE

from django.db import models

# Create your models here.
class UserRegister_Model(models.Model):
    name = models.CharField(max_length=50)
    email = models.EmailField(max_length=30)
    password = models.CharField(max_length=10)
    phoneno = models.CharField(max_length=15)
    address = models.CharField(max_length=500)

class UserAdd_Model(models.Model):
    uregid = models.ForeignKey(UserRegister_Model,
	on_delete=models.CASCADE,)
    entity = models.CharField(max_length=100)
    year = models.IntegerField()
    records = models.CharField(max_length=1000)
    organizationtype=models.CharField(max_length=1000)
    method = models.CharField(max_length=100)
    adddata = models.CharField(max_length=500)
    attackresult = models.CharField(max_length=500)
    time = models.CharField(max_length=100)
