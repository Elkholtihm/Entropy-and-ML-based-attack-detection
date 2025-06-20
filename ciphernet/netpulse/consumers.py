# netpulse/consumers.py
import json
import mysql.connector
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
from decouple import Config,RepositoryEnv
from .dashboard_data import DashboardData


import os
import django
from django.conf import settings
from django.db.models import Max
from django.utils.timezone import now, timedelta

# Ensure project root is in sys.path
# sys.path.append('C:\\Users\\dell\\Desktop\\ciphernet')

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ciphernet.settings')
django.setup()

# class StreamConsumer(AsyncWebsocketConsumer):
import json
import random
import asyncio
from channels.generic.websocket import AsyncWebsocketConsumer
import datetime
from decouple import config

class StreamConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Accept the WebSocket connection when a client connects
        await self.accept()
        self.dashboard_data = DashboardData()
        # Start sending Huffman data in the background
        asyncio.create_task(self.send_huffman_data())

    async def disconnect(self, close_code):
        # Handle disconnection (no cleanup needed for now)
        pass

    async def send_huffman_data(self):
        # Continuously send Huffman data
        while True:
            try:
                # Fetch Huffman data using sync_to_async to handle synchronous ORM calls
                data = await sync_to_async(self.dashboard_data.get_huffman_data)()
                # Send the data as a JSON string to the client
                await self.send(text_data=json.dumps(data))
            except Exception as e:
                # Send empty data to prevent client errors
                await self.send(text_data=json.dumps({}))
            # Wait 1 second before sending the next update
            await asyncio.sleep(1)




from asgiref.sync import sync_to_async

class CardsConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        await self.accept()
        self.dashboard_data = DashboardData()
        asyncio.create_task(self.send_cards_data())

    async def disconnect(self, close_code):
        pass

    async def send_cards_data(self):
        while True:
            try:
                # Fetch data using sync_to_async to handle synchronous ORM calls
                data = await sync_to_async(self.dashboard_data.get_cards)()
                # Send the data as a JSON string to the client
                await self.send(text_data=json.dumps(data))
            except Exception as e:
                print(f"Error fetching cards data: {e}")
                # Send empty data to prevent client errors
                await self.send(text_data=json.dumps({}))
            await asyncio.sleep(0.001)