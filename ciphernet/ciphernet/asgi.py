import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
import netpulse.routing  # Import your app's routing configuration

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings')

# The main ASGI application
application = ProtocolTypeRouter({
    # Standard HTTP requests go to Django's normal ASGI application
    "http": get_asgi_application(),
    
    # WebSocket requests go through the AuthMiddlewareStack and then to your app's WebSocket URL patterns
    "websocket": AuthMiddlewareStack(
        URLRouter(
            netpulse.routing.websocket_urlpatterns
        )
    ),
})