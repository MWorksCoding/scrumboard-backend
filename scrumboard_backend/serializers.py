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
    

class TaskSerializer(serializers.ModelSerializer):
    assigned_to = ContactSerializer(many=True)
    category = CategorySerializer()

    class Meta:
        model = Task
        fields = '__all__'



class UserListSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "username", "color", "first_name", "last_name"]
