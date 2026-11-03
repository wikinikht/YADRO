"""
Pyrogram bot behind tg-ws-proxy-server SOCKS5 bridge (works inside RF).

Pyrogram always speaks an obfuscated MTProto transport over its TCP
connection, so point it at the local SOCKS5 bridge (127.0.0.1:1080 by
default, see socks5 section of tgws-server.yaml).

    pip install "kurigram[socks]" tgcrypto   # fork of pyrogram, socks extra
"""

import os

from pyrogram import Client, filters

API_ID = int(os.environ.get('API_ID', '0') or 0)
API_HASH = os.environ.get('API_HASH', '')
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')

app = Client(
    'bot',
    api_id=API_ID,
    api_hash=API_HASH,
    bot_token=BOT_TOKEN,
    proxies={
        'scheme': 'socks5',
        'hostname': '127.0.0.1',
        'port': 1080,
    },
)


@app.on_message(filters.command('ping'))
async def ping(_, message):
    await message.reply('pong (via tg-ws-proxy-server)')


if __name__ == '__main__':
    app.run()
