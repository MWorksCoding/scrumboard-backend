from django.contrib import admin
from .models import Contact, Category, Task, CustomUser

admin.site.register(Contact)
admin.site.register(Category)
admin.site.register(Task)
admin.site.register(CustomUser)