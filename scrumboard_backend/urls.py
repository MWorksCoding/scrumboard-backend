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
from scrumboard.views import LoginView, LogoutView, TaskView, CategoriesView, UserListView, ContactView, UserDetailView, CreateUserView, ResetPasswordView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('login/', LoginView.as_view()),
    path('tasks/', TaskView.as_view()),
    path('tasks/<int:pk>/', TaskView.as_view()),
    path('categories/', CategoriesView.as_view()),
    path('contacts/', ContactView.as_view()),
    path('contacts/<int:pk>/', ContactView.as_view()),
    path('users/', UserListView.as_view()),
    path('user-settings/<str:username>/', UserDetailView.as_view()),
    path('scrumboard/summary/', TaskView.as_view()),
    path('scrumboard/summary/<int:pk>/', TaskView.as_view()),
    path('logout/', LogoutView.as_view()),
    path('create-user/', CreateUserView.as_view()),
    path('reset-password/<str:email>/', ResetPasswordView.as_view()),
]