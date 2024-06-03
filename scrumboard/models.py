from django.db import models
from django.conf import settings
import datetime
from django.contrib.auth.models import AbstractUser

class CustomUser(AbstractUser):
    color = models.CharField(max_length=20)
    email = models.CharField(max_length=30, unique=True)
    phone = models.CharField(max_length=30)
    
class Contact(models.Model):
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    color = models.CharField(max_length=20)
    email = models.CharField(max_length=30)
    phone = models.CharField(max_length=30)
    
class Category(models.Model):
    name = models.CharField(max_length=100)
    color = models.CharField(max_length=20)
    
class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=300)
    created_at = models.DateField(default=datetime.date.today)
    due_date = models.DateField(default=datetime.date.today)
    priority = models.CharField(max_length=20, default="medium")
    assigned_to = models.ManyToManyField(CustomUser, related_name="assigned_tasks")
    category = models.ForeignKey(Category, on_delete=models.DO_NOTHING, default=None)
    author = models.ForeignKey(CustomUser, on_delete=models.DO_NOTHING)
    status = models.CharField(max_length=20, default="todo")

