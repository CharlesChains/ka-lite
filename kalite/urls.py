from django.conf import settings
from django.conf.urls import include, patterns, url
from views import index

urlpatterns = patterns(
url(r'^index.html', index))