from django.db import models
from django.conf import settings
import datetime
from django.contrib.auth.models import AbstractUser

# Create your models here.
# class TodoItem(models.Model):
#     title = models.CharField(max_length=100)
#     author = models.ForeignKey(
#         settings.AUTH_USER_MODEL,
#         on_delete=models.CASCADE,
#     )
#     created_at = models.DateTimeField(default=datetime.now)
#     checked = models.BooleanField(default=False)

#     def __str__(self):
#         return f'({self.id})  {self.title}'


class CustomUser(AbstractUser):
    color = models.CharField(max_length=20, blank=True, null=True)
    
class Contact(models.Model):
    first_name = models.CharField(max_length=20)
    last_name = models.CharField(max_length=20)
    email = models.CharField(max_length=30)
    phone = models.CharField(max_length=20)
    color = models.CharField(max_length=20)
    def __str__(self) -> str:
        return self.name
    
class Category(models.Model):
    name = models.CharField(max_length=100)
    color = models.CharField(max_length=100)
    
    def __str__(self) -> str:
        return self.name
    
    
class Task(models.Model):
    title = models.CharField(max_length=100)
    description = models.CharField(max_length=300)
    created_at = models.DateField(default=datetime.date.today)
    due_date = models.DateField(default=datetime.date.today)
    priority = models.CharField(max_length=20, default="medium")
    assigned_to = models.ManyToManyField(Contact)
    category = models.ForeignKey(Category, on_delete=models.DO_NOTHING, default=None)
    author = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    status = models.CharField(max_length=20, default="todo")
    
    def __str__(self) -> str:
        return self.title

