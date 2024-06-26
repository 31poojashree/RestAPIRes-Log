from rest_framework import serializers
from .models import User  # Adjust the import to match your User model location

#Registration Serialization
class UserRegistrationSerializer(serializers.ModelSerializer):
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ['name', 'email', 'password', 'password2']  # Adjust these fields based on your User model

    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm password doesn't match")
        return data

    def create(self, validated_data):
        validated_data.pop('password2')
        user = User.objects.create_user(**validated_data)
        return user
    
#Login Serialization
class UserLoginSerializer(serializers.ModelSerializer):
    email=serializers.EmailField(max_length=255)
    class Meta:
        model = User
        fields = ["email", "password"]
        
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email','name']
        
class UserChangePasswordSerialer(serializers.ModelSerializer):
    password =serializers.CharField(max_length=200, style={'input_type':'password'},write_only=True)
    password2 =serializers.CharField(max_length=200, style={'input_type':'password'},write_only=True)
    class Meta:
        model = User
        fields = ['password','password2']
        
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        user= self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm password doesn't match")
        user.set_password(password)
        user.save()
        return data