/**
 * Bot API mirror on Cloudflare Workers — for aiogram / python-telegram-bot
 * bots that use HTTP(S) Bot API and therefore cannot go through the
 * MTProto WebSocket tunnel.
 *
 * Deploy (free plan is enough):
 *   1. wrangler login
 *   2. wrangler deploy api-mirror.js --name tgbotapi-mirror
 *   3. attach your own domain in the CF dashboard (workers.dev is
 *      unreliable from RF; a plain domain behind CF works).
 *
 * Bot side (aiogram):
 *   from aiogram import Bot
 *   bot = Bot(token=TOKEN, base="https://api.your-domain.work")
 *   # every standard endpoint is forwarded: /bot<token>/getMe etc.
 *
 * The worker just forwards every request to the real api.telegram.org
 * and streams the answer back. It never stores the token.
 *
 * NOTE: this is the only Bot-API route that does not need your foreign
 * VPS; the MTProto WS tunnel (the main feature of this fork) is for
 * Telethon/Pyrogram bots. See docs/BOTS.md for the full decision tree.
 */

const UPSTREAM = 'https://api.telegram.org';

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const upstream = UPSTREAM + url.pathname + url.search;

    const init = {
      method: request.method,
      headers: new Headers(request.headers),
      body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
      redirect: 'follow',
    };

    // Webhook mode: uncomment and adjust to restrict the path prefix
    // const SECRET_PATH = '/my-secret-42';
    // if (!url.pathname.startsWith(SECRET_PATH)) return new Response(null, { status: 404 });

    return fetch(upstream, init);
  },
};
