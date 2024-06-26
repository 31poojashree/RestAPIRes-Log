from django.shortcuts import render
from rest_framework import status
from rest_framework.views import APIView 
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

#serializer
from rest_framework import serializers

#Account
from account.models import User
from django.contrib.auth import authenticate
from account.serializers import UserRegistrationSerializer, UserLoginSerializer,UserChangePasswordSerialer, UserProfileSerializer

#Token Generate refresh, access
from rest_framework_simplejwt.tokens import RefreshToken 

def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)
    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


#Registration View
class UserRegistrationView(APIView):
    # We are writing this bcoz we need confirm password field in our 
    # Registration Request
    def post(self, request, format=None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({'token':token,'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    # Validating Password and Confirm Password while Registration
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidatioError("Password and Confirm pasword doesn't match")
        return data
    
    def create(self, validate_data):
        return User.objects.create_user(**validate_data) 
 
#Login View   
class UserLoginView(APIView):
     # We are writing this bcoz we need confirm password field in our 
    # Registration Request
    def post(self, request, format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get("email")
            password = serializer.data.get("password")
            user = authenticate(email=email,password=password)
            if user is not None:
             token = get_tokens_for_user(user) # its generate token 
             return Response({'token':token,'msg':'Login Successful'}, status=status.HTTP_200_OK)
            else:
                 return Response({'errors':{'non_field_errors':['Email or password is not valid']}}, status=status.HTTP_404_NOT_FOUND)
                
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
#Profile View  
class UserProfileView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request, format=None):
        serializer = UserProfileSerializer(data=request.data)
        if serializer.is_valid():
            return Response(serializer.data, status=status.HTTP_200_OK)
        else:
         return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
     
#Change Password  
class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, format=None):
        serializer = UserChangePasswordSerialer(data=request.data,context={'user':request.user})
        if serializer.is_valid(raise_exception=True):
           return Response({'msg':'Password Changed Successefully'},status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
    
     

        
    
    
        
        

