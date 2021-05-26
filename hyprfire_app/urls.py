from django.urls import path
from . import views

urlpatterns = [
    path('', views.index, name='index'),
    path('download/<str:user_filename>/<str:start>/<str:end>/', views.download_pcap_snippet, name='download_pcap_snippet'),
    path('collect/<str:user_filename>/<str:start>/<str:end>/', views.collect_packet_data, name='collect_packet_data')
]
