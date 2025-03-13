from django.contrib.auth import authenticate, login, logout
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.authentication import SessionAuthentication, BasicAuthentication
from rest_framework.views import APIView
from rest_framework import status
from django.contrib.auth.models import User
from drf_spectacular.utils import extend_schema

from customer.serializers import LoginSerializer, UserSerializer


class LoginView(APIView):
    @extend_schema(
        request=LoginSerializer,  # Описуємо очікувані параметри
        responses={200: {"message": "Login successful"}, 401: {"error": "Invalid credentials"}}
    )
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data["username"]
            password = serializer.validated_data["password"]
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)
                return Response({"message": "Login successful"}, status=status.HTTP_200_OK)
            return Response({"error": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class UserInfoView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]  # Вимагає логін
    permission_classes = [IsAuthenticated]  # Доступ тільки для авторизованих

    @extend_schema(
        responses={200: UserSerializer},  # Swagger буде бачити структуру User
        description="Отримати інформацію про поточного користувача"
    )
    def get(self, request):
        user = request.user
        serializer = UserSerializer(user)
        return Response(serializer.data)


class LogoutView(APIView):
    permission_classes = [IsAuthenticated]  # Тільки для авторизованих користувачів

    @extend_schema(
        responses={200: {"message": "Logout successful"}},
        description="Вихід із системи (завершення сесії)"
    )
    def post(self, request):
        logout(request)  # Вихід із системи
        return Response({"message": "Logout successful"}, status=status.HTTP_200_OK)
