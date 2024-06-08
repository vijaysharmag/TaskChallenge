from django.urls import path
from user.views import LoginView, RegisterView, CookieTokenRefreshView, LogoutView, UserView, getSubscriptions

app_name = "user"

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('register/', RegisterView.as_view(), name='register'),
    path('refresh-token', CookieTokenRefreshView.as_view()),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('user/', UserView.as_view(), name='user-detail'),
    path('subscriptions', getSubscriptions)
]
