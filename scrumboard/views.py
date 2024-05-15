from django.shortcuts import render
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import Contact, Category, Task, CustomUser
from scrumboard_backend.serializers import (
    TaskSerializer,
    CategorySerializer,
    ContactSerializer,
    UserListSerializer,
)
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from django.contrib.auth.models import User
    

class LoginView(ObtainAuthToken):
    def post(self, request, *args, **kwargs):
        # serializer takes the incoming data (user / password)
        serializer = self.serializer_class(data=request.data,
                                           context={'request': request})
        # check validation
        serializer.is_valid(raise_exception=True)
        # get user from validated data
        user = serializer.validated_data['user']
        # create token or get token if user already logged in
        token, created = Token.objects.get_or_create(user=user)
        return Response({
            'token': token.key,
            'user_id': user.pk,
            'email': user.email
        },
        status=status.HTTP_200_OK,
        )  
        

class LogoutView(APIView):
    
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        print('self' , self)
        print('request' , request)
        token = Token.objects.get(user=request.user)
        token.delete()
        request.auth.delete()
        return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
    
    
class TaskView(APIView):    
    #Authentication with token
    # permission only when authentication is successful
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None, format=None):
        task = Task.objects.all()
        serializer = TaskSerializer(task, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):        
        # Check for all required fields
        required_fields = ['title', 'description', 'due_date', 'category', 'priority', 'assigned_to']
        missing_fields = [field for field in required_fields if field not in request.data]

        if missing_fields:
            return Response({"error": f"Missing fields: {', '.join(missing_fields)}"}, status=status.HTTP_400_BAD_REQUEST)

        # If all required fields are present, proceed with creating the task
        try:
            author = request.user
            new_task = Task.objects.create(
                title=request.data['title'],
                author=author,
                description=request.data['description'],
                due_date=request.data['due_date'],
                category=request.data['category'],
                priority=request.data['priority'],
                assigned_to=request.data['assigned_to']
            )
            serializer = TaskSerializer(new_task)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class CategoriesView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        categorys = Category.objects.all()
        serializer = CategorySerializer(categorys, many=True)
        return Response(serializer.data)
    
    
    
class UserListView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = CustomUser.objects.all()
        print('users', users)
        serializer = UserListSerializer(users, many=True)
        print('serializer', serializer)
        return Response(serializer.data)