from django.shortcuts import render
from rest_framework import viewsets
from .models import Task, User
from .serializers import TaskSerializer, UserSerializer, LoginSerializer, LogoutSerializer, RegisterSerializer, ShowUserSerializer
from rest_framework.response import Response
from rest_framework import status
from django.http import HttpResponse
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework import generics, status, views
from django.urls import reverse
# from knox.models import AuthToken # pip install django-rest-knox
from django.contrib.auth import login, logout
from django.shortcuts import redirect
from rest_framework.decorators import permission_classes
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.exceptions import APIException
from rest_framework.authtoken.models import Token
from django.contrib.auth import authenticate
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework import permissions


# Create your views here.
class TaskViewSet(viewsets.ModelViewSet):
    queryset = Task.objects.all()
    serializer_class = TaskSerializer



class UserViewSet(viewsets.ModelViewSet):
    serializer_class = UserSerializer

    def get_queryset(self):
        queryset = User.objects.all()

        # if not self.request.user.is_superuser:
        #     queryset = queryset.filter(is_staff=False)

        return queryset
    

# Register API
class RegisterAPI(APIView):
    serializer_class = RegisterSerializer
    permission_classes = []
    # renderer_classes = (UserRenderer,)

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        user_data = serializer.data
        user = User.objects.get(email=user_data['email'])
        
        token = RefreshToken.for_user(user).access_token

        return Response({'success': 'Successfully created','user':user_data}, status=status.HTTP_201_CREATED)
    

class LoginAPI(APIView):
    serializer_class = LoginSerializer
    permission_classes = []

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data = request.data)
        serializer.is_valid(raise_exception = True)
        return Response(serializer.data, status=status.HTTP_200_OK)


class LogoutAPI(generics.GenericAPIView):
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = LogoutSerializer

    def post(self, request):

        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response({"message":"Logged Out Successfully"},status=status.HTTP_204_NO_CONTENT) 
