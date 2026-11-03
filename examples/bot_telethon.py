"""
Telethon bot behind tg-ws-proxy-server (works fully inside RF VPS).

Two equivalent routes — pick one:

A) Native MTProto proxy frontend (recommended, no extra hops):

   proxy = ('mtproto', '127.0.0.1', 1443, SECRET)
   # SECRET = full tg:// secret, e.g. 'ee<32hex><domain_hex>' (FakeTLS)
   #      or 'dd<32hex>' (plain). Get it via `tgws-server links`.
   client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)

   Telethon note: for dd-secrets it picks RandomizedIntermediate
   automatically; ee-secrets (FakeTLS) use the Abridged MTProxy mode.

B) SOCKS5 bridge (same listener the Pyrogram bots use):

   proxy = ('socks5', '127.0.0.1', 1080)
   client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)
   # default ConnectionTcpAbridged works out of the box

connect() below performs a full MTProto handshake through the tunnel —
if it succeeds, your VPS can talk to Telegram without a foreign relay.
"""

import asyncio
import os

from telethon import TelegramClient, events

API_ID = int(os.environ.get('API_ID', '0') or 0)
API_HASH = os.environ.get('API_HASH', '')
BOT_TOKEN = os.environ.get('BOT_TOKEN', '')

# --- route A: native MTProto proxy (preferred) -------------------------
TGWS_MTPROTO_SECRET = os.environ.get(
    'TGWS_MTPROTO_SECRET',
    'ee' + '0123456789abcdef0123456789abcdef' + '636c6f7564666c6172652e636f6d',
)
proxy = ('mtproto', '127.0.0.1', 1443, TGWS_MTPROTO_SECRET)

# --- route B: SOCKS5 bridge -------------------------------------------
# proxy = ('socks5', '127.0.0.1', 1080)

client = TelegramClient('bot', API_ID, API_HASH, proxy=proxy)


@client.on(events.NewMessage(pattern='/ping'))
async def ping(event):
    await event.reply('pong (via tg-ws-proxy-server)')


async def main():
    await client.start(bot_token=BOT_TOKEN)
    me = await client.get_me()
    print(f'Bot online: @{me.username} — tunnel works!')
    await client.run_until_disconnected()


if __name__ == '__main__':
    asyncio.run(main())
