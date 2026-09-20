import { verifyNuvemshopSignature } from '../../../../../lib/nuvemshop.js';

export async function POST(request) {
  const rawBody = await request.text();
  const hmacHeader = request.headers.get('x-linkedstore-hmac-sha256');

  let valid;
  try {
    valid = verifyNuvemshopSignature(rawBody, hmacHeader);
  } catch (err) {
    console.error('Erro ao verificar assinatura do webhook LGPD (customer-redact):', err.message);
    return new Response('Configuração ausente no servidor', { status: 500 });
  }

  if (!valid) {
    console.warn('Webhook customer-redact rejeitado: assinatura inválida.');
    return new Response('Assinatura inválida', { status: 401 });
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (err) {
    return new Response('Payload JSON inválido', { status: 400 });
  }

  const customerId = payload.customer?.id || payload.id || 'desconhecido';
  
  // Log seguro (apenas IDs, sem dados pessoais)
  console.log(`[LGPD] Webhook de exclusão de dados de cliente recebido. Evento: ${payload.event || 'customer/redact'} | Store ID: ${payload.store_id} | Customer ID: ${customerId}`);
  
  // Nenhuma ação destrutiva de exclusão de dados é realizada nesta etapa.
  return new Response('OK', { status: 200 });
}
