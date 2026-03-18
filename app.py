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

# --- 1. 配置参数 ---
UUID = os.environ.get('UUID', 'ad56186e-68db-42b5-9692-128a86046d0f')
DOMAIN = os.environ.get('DOMAIN', '')                
SUB_PATH = os.environ.get('SUB_PATH', 'sub')         
NAME = os.environ.get('NAME', 'Serv00-Node')                    
WSPATH = os.environ.get('WSPATH', UUID[:8])          
PORT = int(os.environ.get('SERVER_PORT') or os.environ.get('PORT') or 5551)
AUTO_ACCESS = os.environ.get('AUTO_ACCESS', '').lower() == 'true'
DEBUG = os.environ.get('DEBUG', '').lower() == 'true'

# --- 2. 全局状态与日志 ---
CurrentDomain, CurrentPort, Tls, ISP = DOMAIN, 443, 'tls', 'Unknown'
logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
for m in ['aiohttp.access', 'aiohttp.server', 'aiohttp.client']: logging.getLogger(m).setLevel(logging.WARNING)
logger = logging.getLogger("ProxyServer")

# --- 3. 工具函数 ---
def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try: s.bind(('0.0.0.0', port)); return True
        except: return False

async def get_runtime_info():
    global ISP, CurrentDomain, Tls, CurrentPort
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get('https://api.ip.sb/geoip', timeout=3) as r:
                if r.status == 200:
                    d = await r.json()
                    ISP = f"{d.get('country_code','')}-{d.get('isp','')}".replace(' ', '_')
    except: pass
    
    if not DOMAIN or DOMAIN == 'your-domain.com':
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get('https://api-ipv4.ip.sb/ip', timeout=3) as r:
                    CurrentDomain, Tls, CurrentPort = (await r.text()).strip(), 'none', PORT
        except: CurrentDomain = "127.0.0.1"
    else: CurrentDomain, Tls, CurrentPort = DOMAIN, 'tls', 443

async def resolve_host(host):
    try: ipaddress.ip_address(host); return host
    except: pass
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f'https://dns.google/resolve?name={host}&type=A', timeout=3) as r:
                if r.status == 200:
                    data = await r.json()
                    if data.get('Answer'): return data['Answer'][0]['data']
        except: pass
    return host

# --- 4. 核心代理类 ---
class ProxyHandler:
    def __init__(self, uuid_str):
        self.uuid = uuid_str
        self.uuid_bytes = bytes.fromhex(uuid_str.replace('-', ''))

    async def _forward(self, ws, reader, writer):
        async def ws_to_tcp():
            try:
                async for msg in ws:
                    if msg.type == aiohttp.WSMsgType.BINARY:
                        writer.write(msg.data); await writer.drain()
            except: pass
            finally: writer.close(); await writer.wait_closed()
        async def tcp_to_ws():
            try:
                while True:
                    data = await reader.read(4096)
                    if not data: break
                    await ws.send_bytes(data)
            except: pass
        await asyncio.gather(ws_to_tcp(), tcp_to_ws())

    async def handle_vless(self, ws, data):
        try:
            if data[0] != 0 or data[1:17] != self.uuid_bytes: return False
            i = data[17] + 19
            port = struct.unpack('!H', data[i:i+2])[0]; i += 2
            atyp = data[i]; i += 1
            if atyp == 1: host, i = '.'.join(str(b) for b in data[i:i+4]), i + 4
            elif atyp == 2:
                l = data[i]; i += 1
                host, i = data[i:i+l].decode(), i + l
            else: return False
            await ws.send_bytes(bytes([0, 0]))
            reader, writer = await asyncio.open_connection(await resolve_host(host), port)
            if i < len(data): writer.write(data[i:]); await writer.drain()
            await self._forward(ws, reader, writer); return True
        except: return False

    async def handle_trojan(self, ws, data):
        try:
            received_hash = data[:56].decode('ascii', errors='ignore')
            h1 = hashlib.sha224(self.uuid.encode()).hexdigest()
            h2 = hashlib.sha224(self.uuid.replace('-','').encode()).hexdigest()
            if received_hash not in [h1, h2]: return False
            off = 58 if data[56:58] == b'\r\n' else 56
            if data[off] != 1: return False
            off += 1; atyp = data[off]; off += 1
            if atyp == 1: host, off = '.'.join(str(b) for b in data[off:off+4]), off + 4
            elif atyp == 3:
                l = data[off]; off += 1
                host, off = data[off:off+l].decode(), off + l
            else: return False
            port = struct.unpack('!H', data[off:off+2])[0]; off += 2
            ds = off + 2 if data[off:off+2] == b'\r\n' else off
            reader, writer = await asyncio.open_connection(await resolve_host(host), port)
            if ds < len(data): writer.write(data[ds:]); await writer.drain()
            await self._forward(ws, reader, writer); return True
        except: return False

# --- 5. 路由处理 (含 index.html 保留逻辑) ---
async def websocket_handler(request):
    ws = web.WebSocketResponse(); await ws.prepare(request)
    if f'/{WSPATH}' not in request.path: await ws.close(); return ws
    proxy = ProxyHandler(UUID)
    try:
        msg = await asyncio.wait_for(ws.receive(), timeout=10)
        if msg.type == aiohttp.WSMsgType.BINARY:
            if msg.data[0] == 0: await proxy.handle_vless(ws, msg.data)
            elif len(msg.data) >= 58: await proxy.handle_trojan(ws, msg.data)
    except: pass
    finally: await ws.close()
    return ws

async def http_handler(request):
    # 订阅路径逻辑
    if request.path == f'/{SUB_PATH}':
        await get_runtime_info()
        n = f"{NAME}-{ISP}"
        v = f"vless://{UUID}@{CurrentDomain}:{CurrentPort}?encryption=none&security={Tls}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{n}"
        t = f"trojan://{UUID}@{CurrentDomain}:{CurrentPort}?security={Tls}&sni={CurrentDomain}&fp=chrome&type=ws&host={CurrentDomain}&path=%2F{WSPATH}#{n}"
        return web.Response(text=base64.b64encode(f"{v}\n{t}".encode()).decode() + '\n')
    
    # 根路径渲染逻辑 (保留并优先展示 index.html)
    if request.path == '/':
        if os.path.exists('index.html'):
            try:
                with open('index.html', 'r', encoding='utf-8') as f:
                    return web.Response(text=f.read(), content_type='text/html')
            except Exception as e:
                logger.error(f"Read index.html failed: {e}")
        return web.Response(text='<h4>Service Running</h4>', content_type='text/html')

    return web.Response(status=404, text='Not Found')

# --- 6. 主程序 ---
async def main():
    actual_port = PORT if is_port_available(PORT) else None
    if not actual_port:
        for p in range(PORT + 1, PORT + 50):
            if is_port_available(p): actual_port = p; break
    if not actual_port: logger.error("No ports available!"); return

    app = web.Application()
    app.router.add_get('/', http_handler)
    app.router.add_get(f'/{SUB_PATH}', http_handler)
    app.router.add_get(f'/{WSPATH}', websocket_handler)
    
    runner = web.AppRunner(app); await runner.setup()
    await web.TCPSite(runner, '0.0.0.0', actual_port).start()
    logger.info(f"✅ Server started on {actual_port}")
    
    if AUTO_ACCESS and DOMAIN:
        try:
            async with aiohttp.ClientSession() as s:
                await s.post("https://oooo.serv00.net/add-url", json={"url": f"https://{DOMAIN}/{SUB_PATH}"})
                logger.info("Automatic Access Task added.")
        except: pass
    
    await asyncio.Future()

if __name__ == '__main__':
    try: asyncio.run(main())
    except: pass