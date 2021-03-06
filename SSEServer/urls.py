"""SSEServer URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from api.resources import *
from tastypie.api import Api

ciphertext_resource = CiphertextResource()
map_resource = MapResource()
search_resource = SearchResource();
update_resource = UpdateResource();
delete_resource = DeleteResource();
presign_resource = PresignUrlResource();

v1_api = Api(api_name='v1')
v1_api.register(ciphertext_resource)
v1_api.register(map_resource)
v1_api.register(search_resource)
v1_api.register(update_resource)
v1_api.register(delete_resource)
v1_api.register(presign_resource)


urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/', include(v1_api.urls)),
]