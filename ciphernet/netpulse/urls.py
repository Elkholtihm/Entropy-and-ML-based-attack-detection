from django.urls import path
from .views import HomeView , DashboardView 
from django.views.generic import TemplateView

urlpatterns = [
path('', HomeView.as_view(), name='home'),
#path("dashboard/", DashboardView.as_view(), name="dashboard"),
path('socket-test/', TemplateView.as_view(template_name='socket.html')),
path('dashboard/', DashboardView.as_view(), name='dashboard'),
]