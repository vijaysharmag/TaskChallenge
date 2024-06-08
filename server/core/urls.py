from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi
from django.contrib import admin
from django.urls import include, path


schema_view = get_schema_view(
   openapi.Info(
      title="challenge APi",
      default_version='v1',
      description="API for retrieving user details and other operations.",
      terms_of_service="https://www.google.com/policies/terms/",
      contact=openapi.Contact(email="contact@snippets.local"),
      license=openapi.License(name="BSD License"),
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    path('admin/', admin.site.urls),
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
    path('api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    path('auth/', include('user.urls', namespace='user')),
    path('transaction/', include('transaction.urls', namespace='transaction'))
]