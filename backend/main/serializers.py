from rest_framework import serializers
from .models import Task, User
from django.contrib.auth.password_validation import validate_password
from requests import Response
from django.contrib.auth import authenticate
from rest_framework.exceptions import APIException
from fuzzywuzzy import fuzz
from rest_framework.exceptions import AuthenticationFailed
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework import status
from django.contrib.auth.hashers import check_password



class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = Task
        fields = "__all__"


class UserSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = User
        fields = ["id", "uuid", "username", "email", "password", "profile_image",
                  "first_name_en", "last_name_en", "first_name_ar", "last_name_ar", "is_superuser", ]
        lookup_field = 'username'
        ordering = ['-id']

    def get_serializer_context(self):
        context = super().get_serializer_context()
        context["user_id"] = self.kwargs['user_id']
        context["query_params"] = self.request.query_params
        return context
    
    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        max_similarity = 70  # Percentage of similarity

        if fuzz.ratio(password.lower(), username.lower()) > max_similarity:
            raise serializers.ValidationError("The password is too similar to the username.")

        return attrs
    
    def create(self, validated_data):
        username = validated_data.pop('username')
        password = validated_data.pop('password')
        email = validated_data.pop('email')

        user = User.objects.create_user(email=email, 
            username=username, password=password, **validated_data)
        
        return user

    def update(self, instance, validated_data):

        instance.username = validated_data.get("username")
        instance.email = validated_data.get("email")
        instance.first_name_en = validated_data.get("first_name_en")
        instance.last_name_en = validated_data.get("last_name_en")
        instance.first_name_ar = validated_data.get("first_name_ar")
        instance.last_name_ar = validated_data.get("last_name_ar")

        if "profile_image" in validated_data:
            print(validated_data["profile_image"])
            instance.profile_image = validated_data.get("profile_image")

        password = validated_data['password']
        if check_password(password, instance.password):
            print("Checked")
        elif password == instance.password:
            print("checked")
        else:
            print("unchecked")
            instance.set_password(password)
        instance.save()
        return instance


class ShowUserSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "uuid", "username", "email", ]


class RegisterSerializer(serializers.ModelSerializer):

    class Meta:
        model = User
        fields = ["id", "username", "email", "password", "profile_image",
                  "first_name_en", "last_name_en", "first_name_ar", "last_name_ar", ]
        extra_kwargs = {'password': {'write_only': True}}
    
    def validate(self, attrs):
        username = attrs.get('username')
        password = attrs.get('password')

        max_similarity = 70  # Percentage of similarity

        if fuzz.ratio(password.lower(), username.lower()) > max_similarity:
            raise serializers.ValidationError("The password is too similar to the username.")

        return attrs
    
    def create(self, validated_data):

        username = validated_data.pop('username')
        password = validated_data.pop('password')
        # self.validate_password(password)
        email = validated_data.pop('email')

        user = User.objects.create_user(email=email, 
            username=username, password=password, **validated_data)
        
        return user


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField()
    password = serializers.CharField(write_only=True)
    tokens = serializers.SerializerMethodField()

    class Meta:
        fields = ['username', 'password', 'tokens']

    def get_tokens(self, obj):
        refresh_token = RefreshToken.for_user(obj)
        tokens = {
            'refresh': str(refresh_token),
            'access': str(refresh_token.access_token),
        }
        return tokens


    def validate(self, data):
        username = data.get('username')
        password = data.get('password')
        user = authenticate(username=username, password=password)

        response = user

        if not user:
            raise AuthenticationFailed("Invalid credentials")
            # return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)
        if not user.is_active:
            raise AuthenticationFailed("Account is not active, please contact admin")
            # return Response({'error': 'Account is not active, please contact admin'}, status=status.HTTP_403_FORBIDDEN)

        return response


class LogoutSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):

        try:
            RefreshToken(self.token).blacklist()
            response = {'success': 'New token is given'}

        except TokenError:
            # raise serializers.ValidationError(
            #     self.default_error_message)
            response = self.default_error_message
            
        return response
