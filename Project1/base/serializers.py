from rest_framework import routers, serializers, viewsets
from .models import Todo
from django.contrib.auth import authenticate

class loginSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()
        
class UserRegisterSerializer(serializers.Serializer):
    email = serializers.CharField()
    password = serializers.CharField()

class TodoSerializer(serializers.Serializer):
    title = serializers.CharField(max_length=100)
    details = serializers.CharField(max_length=300)

class TododResponseSerializer(serializers.ModelSerializer):
    class Meta:
        model = Todo
        fields='__all__'
    
        