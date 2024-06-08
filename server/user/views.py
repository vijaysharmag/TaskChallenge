from django.contrib.auth import authenticate
from django.conf import settings
from django.middleware import csrf
from rest_framework import exceptions as rest_exceptions, response, decorators as rest_decorators, permissions as rest_permissions
from rest_framework_simplejwt import tokens, views as jwt_views, serializers as jwt_serializers, exceptions as jwt_exceptions
from user import serializers, models
import stripe

from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.exceptions import AuthenticationFailed
from rest_framework import generics
from rest_framework.permissions import IsAuthenticated
from rest_framework.exceptions import ParseError
from django.contrib.auth import get_user_model
from rest_framework.exceptions import NotFound
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi

stripe.api_key = settings.STRIPE_SECRET_KEY
prices = {
    settings.WORLD_INDIVIDUAL: "world_individual",
    settings.WORLD_GROUP: "world_group",
    settings.WORLD_BUSINESS: "world_business",
    settings.UNIVERSE_INDIVIDUAL: "universe_individual",
    settings.UNIVERSE_GROUP: "universe_group",
    settings.UNIVERSE_BUSINESS: "universe_business"
}


def get_user_tokens(user):
    refresh = tokens.RefreshToken.for_user(user)
    return {
        "refresh_token": str(refresh),
        "access_token": str(refresh.access_token)
    }



class LoginView(generics.GenericAPIView):
    serializer_class = serializers.LoginSerializer
    permission_classes = [AllowAny]  # No permissions required
    

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        email = serializer.validated_data["email"]
        password = serializer.validated_data["password"]

        user = authenticate(email=email, password=password)

        if user is not None:
            tokens = get_user_tokens(user)

            res = Response(tokens)
            res.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE'],
                value=tokens["access_token"],
                expires=settings.SIMPLE_JWT['ACCESS_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            res.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=tokens["refresh_token"],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            res["X-CSRFToken"] = csrf.get_token(request)
            return res

        raise AuthenticationFailed("Email or Password is incorrect!")


class RegisterView(generics.CreateAPIView):
    serializer_class = serializers.RegistrationSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        if user is not None:
            return Response("Registered!")
        else:
            raise AuthenticationFailed("Invalid credentials!")


class LogoutView(generics.GenericAPIView):

    permission_classes = [IsAuthenticated]

    def post(self, request, *args, **kwargs):
        try:
            refresh_token = request.COOKIES.get(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            
            if refresh_token is None:
                raise ParseError("No refresh token found in cookies")
            
            token = tokens.RefreshToken(refresh_token)
            token.blacklist()

            
            res = Response("Successfully logged out!")
            res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE'])
            res.delete_cookie(settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'])
            res.delete_cookie("X-CSRFToken")
            res.delete_cookie("csrftoken")
            res["X-CSRFToken"] = None

            return res

        except Exception as e:
            raise ParseError(f"Invalid token: {str(e)}")

class CookieTokenRefreshSerializer(jwt_serializers.TokenRefreshSerializer):
    refresh = None

    def validate(self, attrs):
        attrs['refresh'] = self.context['request'].COOKIES.get('refresh')
        if attrs['refresh']:
            return super().validate(attrs)
        else:
            raise jwt_exceptions.InvalidToken(
                'No valid token found in cookie \'refresh\'')


class CookieTokenRefreshView(jwt_views.TokenRefreshView):
    serializer_class = CookieTokenRefreshSerializer

    def finalize_response(self, request, response, *args, **kwargs):
        if response.data.get("refresh"):
            response.set_cookie(
                key=settings.SIMPLE_JWT['AUTH_COOKIE_REFRESH'],
                value=response.data['refresh'],
                expires=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'],
                secure=settings.SIMPLE_JWT['AUTH_COOKIE_SECURE'],
                httponly=settings.SIMPLE_JWT['AUTH_COOKIE_HTTP_ONLY'],
                samesite=settings.SIMPLE_JWT['AUTH_COOKIE_SAMESITE']
            )

            del response.data["refresh"]
        response["X-CSRFToken"] = request.COOKIES.get("csrftoken")
        return super().finalize_response(request, response, *args, **kwargs)


class UserView(generics.RetrieveAPIView):
    serializer_class = serializers.UserSerializer
    permission_classes = [IsAuthenticated]

    def get_object(self):
        try:
            # Retrieve the authenticated user
            return get_user_model().objects.get(id=self.request.user.id)
        except get_user_model().DoesNotExist:
            raise NotFound("User not found")
    
    def get(self, request, *args, **kwargs):
        """
        Overriding the get method to provide custom response handling if needed.
        """
        user = self.get_object()
        serializer = self.get_serializer(user)
        return Response(serializer.data)


@rest_decorators.api_view(["GET"])
@rest_decorators.permission_classes([rest_permissions.IsAuthenticated])
def getSubscriptions(request):
    try:
        user = models.User.objects.get(id=request.user.id)
    except models.User.DoesNotExist:
        return response.Response(status_code=404)

    subscriptions = []
    customer = stripe.Customer.search(query=f'email:"{user.email}"')
    if "data" in customer:
        if len(customer["data"]) > 0:
            for _customer in customer["data"]:
                subscription = stripe.Subscription.list(customer=_customer["id"])
                if "data" in subscription:
                    if len(subscription["data"]) > 0:
                        for _subscription in subscription["data"]:
                            if _subscription["status"] == "active":
                                subscriptions.append({
                                    "id": _subscription["id"],
                                    "start_date": str(_subscription["start_date"]),
                                    "plan": prices[_subscription["plan"]["id"]]
                                })

    return response.Response({"subscriptions": subscriptions}, 200)
