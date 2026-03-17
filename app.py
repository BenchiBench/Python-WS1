#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import socket
import struct
import hashlib
import base64
import asyncio
import aiohttp
import logging
import ipaddress
from aiohttp import web

# ================= 配置 =================
UUID = os.environ.get('UUID', 'ad56186e-68db-42b5-9692-128a86046d0f')
DOMAIN = os.environ.get('DOMAIN', '')
SUB_PATH = os.environ.get('SUB_PATH', 'sub')
NAME = os.environ.get('NAME', '')
WSPATH = os.environ.get('WSPATH', UUID[:8])
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 3000)
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

CurrentDomain = DOMAIN
CurrentPort = 443
Tls = 'tls'
ISP = ''

DNS_SERVERS = ['8.8.4.4', '1.1.1.1']
BLOCKED_DOMAINS = [
    'speedtest.net', 'fast.com', 'speedtest.cn',
    'speed.cloudflare.com', 'speedof.me'
]

logging.basicConfig(
    level=logging.DEBUG if DEBUG else logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ================= 工具函数 =================
def is_port_available(port, host='0.0.0.0'):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False

def find_available_port(start_port):
    for port in range(start_port, start_port + 100):
        if is_port_available(port):
            return port
    return None

def is_blocked_domain(host: str) -> bool:
    return any(host.endswith(d) for d in BLOCKED_DOMAINS)

async def resolve_host(host: str) -> str:
    try:
        ipaddress.ip_address(host)
        return host
    except:
        pass

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f'https://dns.google/resolve?name={host}&type=A') as resp:
                data = await resp.json()
                for ans in data.get('Answer', []):
                    if ans.get('type') == 1:
                        return ans.get('data')
    except:
        pass

    return host

# ================= 代理处理 =================
class ProxyHandler:
    def __init__(self, uuid: str):
        self.uuid_bytes = bytes.fromhex(uuid)

    async def handle_vless(self, ws, data):
        if len(data) < 18 or data[0] != 0:
            return False
        if data[1:17] != self.uuid_bytes:
            return False

        i = data[17] + 19
        port = struct.unpack('!H', data[i:i+2])[0]
        i += 2
        atyp = data[i]
        i += 1

        if atyp == 1:
            host = '.'.join(map(str, data[i:i+4]))
            i += 4
        elif atyp == 2:
            l = data[i]
            i += 1
            host = data[i:i+l].decode()
            i += l
        else:
            return False

        if is_blocked_domain(host):
            await ws.close()
            return False

        await ws.send_bytes(b'\x00\x00')
        reader, writer = await asyncio.open_connection(await resolve_host(host), port)

        async def ws_to_tcp():
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()

        async def tcp_to_ws():
            while True:
                d = await reader.read(4096)
                if not d:
                    break
                await ws.send_bytes(d)

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
        return True

    async def handle_trojan(self, ws, data):
        if len(data) < 58:
            return False

        pwd = hashlib.sha224(UUID.encode()).hexdigest()
        if data[:56].decode(errors='ignore') != pwd:
            return False

        offset = 58
        cmd = data[offset]
        offset += 1

        atyp = data[offset]
        offset += 1

        if atyp == 1:
            host = '.'.join(map(str, data[offset:offset+4]))
            offset += 4
        elif atyp == 3:
            l = data[offset]
            offset += 1
            host = data[offset:offset+l].decode()
            offset += l
        else:
            return False

        port = struct.unpack('!H', data[offset:offset+2])[0]

        if is_blocked_domain(host):
            await ws.close()
            return False

        reader, writer = await asyncio.open_connection(await resolve_host(host), port)

        async def ws_to_tcp():
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.BINARY:
                    writer.write(msg.data)
                    await writer.drain()

        async def tcp_to_ws():
            while True:
                d = await reader.read(4096)
                if not d:
                    break
                await ws.send_bytes(d)

        await asyncio.gather(ws_to_tcp(), tcp_to_ws())
        return True

# ================= WebSocket =================
async def websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)

    proxy = ProxyHandler(UUID.replace('-', ''))

    try:
        msg = await ws.receive()
        data = msg.data

        if await proxy.handle_vless(ws, data):
            return ws
        if await proxy.handle_trojan(ws, data):
            return ws

        await ws.close()
    except:
        await ws.close()

    return ws

# ================= HTTP =================
async def http_handler(request):
    if request.path == f'/{SUB_PATH}':
        name = NAME or "node"
        vless = f"vless://{UUID}@{DOMAIN}:443?type=ws&path=/{WSPATH}#{name}"
        trojan = f"trojan://{UUID}@{DOMAIN}:443?type=ws&path=/{WSPATH}#{name}"

        sub = base64.b64encode(f"{vless}\n{trojan}".encode()).decode()
        return web.Response(text=sub)

    return web.Response(text="OK")

# ================= 启动 =================
async def main():
    port = PORT
    if not is_port_available(port):
        port = find_available_port(port + 1)

    app = web.Application()
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', port)
    await site.start()

    logger.info(f"Running on port {port}")

    await asyncio.Future()

if __name__ == '__main__':
    asyncio.run(main())