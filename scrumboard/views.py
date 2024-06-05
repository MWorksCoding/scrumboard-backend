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
    """
    Handle user login by validating credentials and returning a token.
    
    Methods
    -------
    post(request, *args, **kwargs)
        Validate user credentials and return an authentication token.
    """
    def post(self, request, *args, **kwargs):
        try:
            serializer = self.serializer_class(data=request.data,
                                               context={'request': request})
            serializer.is_valid(raise_exception=True)
            user = serializer.validated_data['user']
            token, created = Token.objects.get_or_create(user=user)
            return Response({
                'token': token.key,
                'user_id': user.pk,
                'username': user.username,
                'email': user.email
            }, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class LogoutView(APIView):
    """
    Handle user logout by deleting the user's token.
    
    Methods
    -------
    post(request)
        Delete the user's authentication token.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            token = Token.objects.get(user=request.user)
            token.delete()
            request.auth.delete()
            return Response({"message": "Successfully logged out."}, status=status.HTTP_200_OK)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    
class TaskView(APIView):    
    """
    Handle CRUD operations for tasks.
    
    Methods
    -------
    get(request, pk=None, format=None)
        Retrieve all tasks or a specific task by ID.
    post(request, format=None)
        Create a new task.
    put(request, pk, format=None)
        Update an existing task by ID.
    delete(request, pk, format=None)
        Delete a task by ID.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, pk=None, format=None):
        try:
            if pk:
                task = get_object_or_404(Task, pk=pk)
                serializer = TaskSerializer(task)
            else:
                task = Task.objects.all()
                serializer = TaskSerializer(task, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def post(self, request, format=None):     
        try:
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
                task = serializer.save(
                    assigned_to=assigned_to,
                    author=author
                )
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
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
    """
    Handle retrieval of all categories.
    
    Methods
    -------
    get(request)
        Retrieve all categories.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            categories = Category.objects.all()
            serializer = CategorySerializer(categories, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    
class UserListView(APIView):
    """
    Handle retrieval of all users.
    
    Methods
    -------
    get(request)
        Retrieve all users.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request):
        try:
            users = CustomUser.objects.all()
            serializer = UserListSerializer(users, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        

class ContactView(APIView):
    """
    Handle CRUD operations for contacts.
    
    Methods
    -------
    get(request, pk=None, format=None)
        Retrieve all contacts or a specific contact by ID.
    post(request, format=None)
        Create a new contact.
    put(request, pk, format=None)
        Update an existing contact by ID.
    delete(request, pk, format=None)
        Delete a contact by ID.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, pk=None, format=None):
        try:
            if pk:
                contact = get_object_or_404(Contact, pk=pk)
                serializer = ContactSerializer(contact)
            else:
                contacts = Contact.objects.all()
                serializer = ContactSerializer(contacts, many=True)
            return Response(serializer.data)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
    def post(self, request, format=None):
        try:
            serializer = ContactSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    
    def put(self, request, pk, format=None):
        try:
            contact = get_object_or_404(Contact, pk=pk)
            serializer = ContactSerializer(contact, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except Contact.DoesNotExist:
            return Response({'error': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


    def delete(self, request, pk, format=None):
        try:
            contact = get_object_or_404(Contact, pk=pk)
            contact.delete()
            return Response({'message': 'Contact deleted successfully'}, status=status.HTTP_204_NO_CONTENT)
        except Contact.DoesNotExist:
            return Response({'error': 'Contact not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
    
    
class UserDetailView(APIView):
    """
    Handle retrieval and update of a specific user by username.
    
    Methods
    -------
    get(request, username)
        Retrieve a user by username.
    put(request, username)
        Update a user by username.
    """
    authentication_classes = [TokenAuthentication]
    permission_classes = [IsAuthenticated]
    
    def get(self, request, username):
        try:
            user = get_object_or_404(CustomUser, username=username)
            serializer = UserListSerializer(user, many=False)
            return Response(serializer.data)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, username):
        try:
            user = get_object_or_404(CustomUser, username=username)
            serializer = UserListSerializer(user, data=request.data, partial=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
class CreateUserView(APIView):
    """
    Handle user creation.
    
    Methods
    -------
    post(request)
        Create a new user.
    """
    def post(self, request):
        try:
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
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        
        
class ResetPasswordView(APIView):
    """
    Handle password reset for a user by email.
    
    Methods
    -------
    get(request, email)
        Retrieve user data by email.
    put(request, email)
        Update user password by email.
    """
    def get(self, request, email):
        try:
            user = get_object_or_404(CustomUser, email=email)
            serializer = UserListSerializer(user)
            return Response(serializer.data)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

    def put(self, request, email):
        try:
            user = get_object_or_404(CustomUser, email=email)
            new_password = request.data.get('password')
            if new_password:
                user.set_password(new_password)
                user.save()
                return Response({'message': 'Password changed successfully'}, status=status.HTTP_200_OK)
            return Response({'error': 'Password not provided'}, status=status.HTTP_400_BAD_REQUEST)
        except CustomUser.DoesNotExist:
            return Response({'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)