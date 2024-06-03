from rest_framework import serializers
from scrumboard.models import Category, Contact, Task, CustomUser

class UserSerializer(serializers.ModelSerializer):  
    class Meta:
        model = CustomUser
        fields = ["id", "username", "color", "first_name", "last_name"]

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'
        
        
class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = '__all__'

class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "username", "color", "first_name", "last_name", "email", "phone"]


class TaskSerializer(serializers.ModelSerializer):
    assigned_to = serializers.PrimaryKeyRelatedField(queryset=CustomUser.objects.all(), many=True)
    category = serializers.PrimaryKeyRelatedField(queryset=Category.objects.all())


    class Meta:
        model = Task
        fields = '__all__'