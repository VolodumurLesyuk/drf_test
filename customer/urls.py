from django.urls import path
from .views import LoginView, UserInfoView, LogoutView

urlpatterns = [
    path('login/', LoginView.as_view(), name='login'),
    path('me/', UserInfoView.as_view(), name='user-info'),
    path('logout/', LogoutView.as_view(), name='logout'),
]
