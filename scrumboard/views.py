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
from django.shortcuts import get_object_or_404
    

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
            'username': user.username,
            'email': user.email
        },
        status=status.HTTP_200_OK,
        )  
        

class LogoutView(APIView):
    
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
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
        author = request.user
        data = request.data.copy()
        data['author'] = author.id
        category_data = data.get('category')
        if isinstance(category_data, dict):
            data['category'] = category_data.get('id')
        serializer = TaskSerializer(data=data)
        if serializer.is_valid():
            assigned_to_id = request.data.get("assigned_to")
            assigned_to = CustomUser.objects.filter(pk__in=assigned_to_id).all()
            author = request.user
            task = serializer.save(
                assigned_to=assigned_to,
                author=author
            )
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    def put(self, request, pk, format=None):
        try:
            task = Task.objects.get(pk=pk)
        except Task.DoesNotExist:
            return Response({'error': 'Task not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = TaskSerializer(task, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request, pk, format=None):
        try:
            task = Task.objects.get(pk=pk)
        except Task.DoesNotExist:
            return Response({'error': 'Task not found'}, status=status.HTTP_404_NOT_FOUND)
        task.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)

        
        
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
        serializer = UserListSerializer(users, many=True)
        return Response(serializer.data)
    

class ContactView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None, format=None):
        if pk:
            try:
                contact = Contact.objects.get(pk=pk)
                serializer = ContactSerializer(contact)
                return Response(serializer.data)
            except Contact.DoesNotExist:
                return Response(status=status.HTTP_404_NOT_FOUND)
        else:
            contacts = Contact.objects.all()
            serializer = ContactSerializer(contacts, many=True)
            return Response(serializer.data)
        
        
    def post(self, request, format=None):
        serializer = ContactSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
    def put(self, request, pk, format=None):
        try:
            contact = Contact.objects.get(pk=pk)
        except Contact.DoesNotExist:
            return Response({'error': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        serializer = ContactSerializer(contact, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, pk, format=None):
        try:
            contact = Contact.objects.get(pk=pk)
        except Contact.DoesNotExist:
            return Response({'error': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        contact.delete()
        return Response({'message': 'Contact deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
    
    
class UserDetailView(APIView):
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, username):
        try:
            user = get_object_or_404(CustomUser, username=username)
            serializer = UserListSerializer(user, many=False)
            return Response(serializer.data)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND) 

    def put(self, request, username):
        try:
            user = get_object_or_404(CustomUser, username=username)
            serializer = UserListSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        
class CreateUserView(APIView):

    def post(self, request):
        first_name = request.data.get("first_name")
        last_name = request.data.get("last_name")
        username = request.data.get("username")
        email = request.data.get("email")
        phone = request.data.get("phone")
        color = request.data.get("color")
        password = request.data.get("password")

        if CustomUser.objects.filter(username=username).exists():
            return Response(
                {"message": "This username already exists"},
                status=status.HTTP_409_CONFLICT,
            )

        if CustomUser.objects.filter(email=email).exists():
            return Response(
                {"message": "This email already exists"},
                status=status.HTTP_409_CONFLICT,
            )

        user = CustomUser.objects.create_user(
            username=username,
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            color=color,
            password=password,
        )

        return Response(
            {"message": "User created successfully"}, status=status.HTTP_201_CREATED
        )
        
        
class ResetPasswordView(APIView):
    
    def get(self, request, email):
        print(f"Received request to reset password for email: {email}")  # Debugging line
        user = get_object_or_404(CustomUser, email=email)
        serializer = UserListSerializer(user)
        return Response(serializer.data)

    def put(self, request, email):
        user = get_object_or_404(CustomUser, email=email)
        # serializer = UserListSerializer(user, data=request.data, partial=True)
        # if serializer.is_valid():
        #     serializer.save()
        #     return Response(serializer.data)
        # return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        new_password = request.data.get('password')
        if new_password:
            user.set_password(new_password)
            user.save()
            return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
        return Response({'error': 'Password not provided'}, status=status.HTTP_400_BAD_REQUEST)