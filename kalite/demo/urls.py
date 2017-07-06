from django.conf.urls import patterns, url

urlpatterns = patterns(
    __package__ + '.views',
    url(r'^$', 'index', name='index'),
    url(r'^attrs/$', 'attrs', name='attrs'),
    url(r'^metadata/$', 'metadata', name='metadata'),
)
