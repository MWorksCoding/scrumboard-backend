"""
URL configuration for scrumboard_backend project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from scrumboard.views import LoginView, LogoutView, TaskView, CategoriesView, UserListView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', LoginView.as_view()),
    path('login/', LoginView.as_view()),
    path('tasks/', TaskView.as_view()),
    path('tasks/<int:pk>/', TaskView.as_view()),
    path("categories/", CategoriesView.as_view()),
    path("users/", UserListView.as_view()),
    path('scrumboard/summary/', TaskView.as_view()),
    path('scrumboard/summary/<int:pk>/', TaskView.as_view()),
    path('logout/', LogoutView.as_view()),
]

# Hier weiter machen: Add Task view hinzufügen für den POst request!