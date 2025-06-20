from django.shortcuts import render , redirect, get_object_or_404
from django.http import HttpResponse , JsonResponse
from django.template import loader
from django.views import View
import random
# Create your views here.
class HomeView(View):
    def get(self, request):
        return render(request, 'home.html')
class DashboardView(View):
    def get(self, request):
        return render(request, 'dashboard.html')



# class DashboardDataAPI(View):
#     def get(self, request):
#         data = {
#             'total_traffic': random.randint(1000, 5000),  # Simulating traffic data (in GB)
#             'anomalies_detected': random.randint(1, 100),  # Simulating anomaly count
#             'high_alerts': random.randint(0, 10),  # Simulating high alerts
#             'data_processed': random.randint(500, 3000),  # Simulating data processed (in MB)
#             'active_connections': random.randint(100, 500),  # Simulating active connections
#         }
#         return JsonResponse(data)

# class TrafficDataAPI(View):
#     def get(self, request):
#         # Simulating weekly traffic data for the chart (in GB)
#         traffic_data = [random.randint(100, 300) for _ in range(7)]  # 7 random values for the week
        
#         data = {
#             'traffic_data': traffic_data,  # Weekly traffic data
#         }
        
#         return JsonResponse(data)