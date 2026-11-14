import express from 'express';
import crypto from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const required = ['SUPABASE_URL', 'SUPABASE_ANON_KEY', 'SUPABASE_SERVICE_ROLE_KEY', 'MP_ACCESS_TOKEN', 'SITE_URL'];
for (const key of required) if (!process.env[key]) console.warn(`Variável ausente: ${key}`);

const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
const allowedOrigins = (process.env.SITE_URL || '').split(',').map(v => v.trim()).filter(Boolean);
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (!origin || allowedOrigins.includes(origin)) {
    if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

const admin = createClient(process.env.SUPABASE_URL || 'https://invalid.supabase.co', process.env.SUPABASE_SERVICE_ROLE_KEY || 'missing', { auth: { persistSession: false, autoRefreshToken: false } });
const PRICE = 49.90;
const FREE_EMAIL = (process.env.FREE_ACCESS_EMAIL || '').trim().toLowerCase();

async function auth(req, res, next) {
  try {
    const token = (req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!token) return res.status(401).json({ error: 'Faça login novamente.' });
    const { data, error } = await admin.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: 'Sessão inválida. Entre novamente.' });
    req.user = data.user;
    next();
  } catch (e) { next(e); }
}

async function ownedStore(storeId, userId) {
  const { data, error } = await admin.from('stores').select('*').eq('id', storeId).eq('user_id', userId).maybeSingle();
  if (error) throw error;
  return data;
}

app.get('/health', (_req, res) => res.json({ ok: true, service: 'ESFONT STORE API' }));

app.post('/api/store-status', auth, async (req, res, next) => {
  try {
    const store = await ownedStore(req.body?.store_id, req.user.id);
    if (!store) return res.status(404).json({ error: 'Loja não encontrada.' });
    if (store.status !== 'ACTIVE' && FREE_EMAIL && (req.user.email || '').toLowerCase() === FREE_EMAIL) {
      const { data, error } = await admin.from('stores').update({ status: 'ACTIVE' }).eq('id', store.id).eq('user_id', req.user.id).select('*').single();
      if (error) throw error;
      return res.json({ store: data, free: true });
    }
    return res.json({ store });
  } catch (e) { next(e); }
});

app.post('/api/create-pix', auth, async (req, res, next) => {
  try {
    const store = await ownedStore(req.body?.store_id, req.user.id);
    if (!store) return res.status(404).json({ error: 'Loja não encontrada.' });
    if (store.status === 'ACTIVE') return res.json({ active: true, message: 'Sua loja já está ativa.' });
    if (FREE_EMAIL && (req.user.email || '').toLowerCase() === FREE_EMAIL) {
      const { error } = await admin.from('stores').update({ status: 'ACTIVE' }).eq('id', store.id).eq('user_id', req.user.id);
      if (error) throw error;
      return res.json({ active: true, free: true, message: 'Acesso gratuito autorizado.' });
    }
    if (!process.env.MP_ACCESS_TOKEN) return res.status(503).json({ error: 'Mercado Pago ainda não foi configurado no servidor.' });

    const idempotencyKey = crypto.randomUUID();
    const mpResponse = await fetch('https://api.mercadopago.com/v1/payments', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
        'X-Idempotency-Key': idempotencyKey
      },
      body: JSON.stringify({
        transaction_amount: PRICE,
        description: `Ativação da loja ${store.name} - ESFONT STORE`,
        payment_method_id: 'pix',
        payer: { email: req.user.email },
        external_reference: store.id,
        notification_url: `${process.env.RENDER_EXTERNAL_URL || process.env.API_URL}/webhooks/mercadopago`
      })
    });
    const payment = await mpResponse.json();
    if (!mpResponse.ok) {
      console.error('Mercado Pago create payment:', payment);
      return res.status(502).json({ error: payment.message || 'Mercado Pago não conseguiu gerar o Pix.' });
    }
    const tx = payment.point_of_interaction?.transaction_data;
    if (!payment.id || !tx?.qr_code) return res.status(502).json({ error: 'Mercado Pago não retornou os dados do Pix.' });
    const { error: saveError } = await admin.from('store_payments').insert({
      store_id: store.id, user_id: req.user.id, mp_payment_id: String(payment.id),
      amount: PRICE, status: payment.status || 'pending', qr_code: tx.qr_code,
      qr_code_base64: tx.qr_code_base64 || null
    });
    if (saveError) throw saveError;
    return res.json({ qr_code: tx.qr_code, qr_code_base64: tx.qr_code_base64 || null, payment_id: payment.id });
  } catch (e) { next(e); }
});

function validSignature(req, dataId) {
  const secret = process.env.MP_WEBHOOK_SECRET;
  if (!secret) return false;
  const signature = req.headers['x-signature'] || '';
  const requestId = req.headers['x-request-id'] || '';
  const parts = Object.fromEntries(signature.split(',').map(part => part.trim().split('=')));
  if (!parts.ts || !parts.v1 || !dataId) return false;
  const manifest = `id:${String(dataId).toLowerCase()};request-id:${requestId};ts:${parts.ts};`;
  const digest = crypto.createHmac('sha256', secret).update(manifest).digest('hex');
  const a = Buffer.from(digest, 'hex');
  const b = Buffer.from(parts.v1, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

app.post('/webhooks/mercadopago', async (req, res) => {
  try {
    const paymentId = req.query['data.id'] || req.body?.data?.id;
    if (!paymentId) return res.sendStatus(200);
    if (!validSignature(req, paymentId)) return res.status(401).send('Invalid signature');
    const mpResponse = await fetch(`https://api.mercadopago.com/v1/payments/${encodeURIComponent(paymentId)}`, {
      headers: { Authorization: `Bearer ${process.env.MP_ACCESS_TOKEN}` }
    });
    const payment = await mpResponse.json();
    if (!mpResponse.ok) return res.sendStatus(502);
    const storeId = payment.external_reference;
    const amount = Number(payment.transaction_amount);
    const { data: saved, error: findError } = await admin.from('store_payments').select('*').eq('mp_payment_id', String(payment.id)).maybeSingle();
    if (findError) throw findError;
    if (!saved || saved.store_id !== storeId || Math.abs(amount - PRICE) > 0.001 || Number(saved.amount) !== PRICE) return res.sendStatus(200);
    const { error: paymentUpdateError } = await admin.from('store_payments').update({ status: payment.status, updated_at: new Date().toISOString() }).eq('id', saved.id);
    if (paymentUpdateError) throw paymentUpdateError;
    if (payment.status === 'approved') {
      const { error: storeUpdateError } = await admin.from('stores').update({ status: 'ACTIVE' }).eq('id', storeId).eq('user_id', saved.user_id);
      if (storeUpdateError) throw storeUpdateError;
    }
    return res.sendStatus(200);
  } catch (e) { console.error('Webhook error:', e); return res.sendStatus(500); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Erro interno do servidor.' });
});

const port = Number(process.env.PORT || 10000);
app.listen(port, '0.0.0.0', () => console.log(`ESFONT STORE API ouvindo na porta ${port}`));
