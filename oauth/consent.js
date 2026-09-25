// Consent page for the My Guppy Tank OAuth server (Supabase Auth). An assistant such as a
// ChatGPT plugin sends the owner here with ?authorization_id=…; they sign in, see which app is
// asking and where it will send them back, and allow or deny. The page then signs out again.
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const show = (id, visible = true) => { $(id).hidden = !visible; };
  const status = text => { $('status').textContent = text; show('status', Boolean(text)); };
  const fail = text => { $('error').textContent = text; show('error', Boolean(text)); };

  // Never work inside a frame: that could trick someone into clicking Allow.
  if (window.top !== window.self) { document.body.textContent = 'Open this page directly.'; return; }

  const id = new URLSearchParams(location.search).get('authorization_id');
  const { url, key } = window.GUPPY_CONNECT ?? {};
  const client = window.supabase.createClient(url, key, { auth: { storageKey: 'guppy-connect-auth', persistSession: true, autoRefreshToken: false, detectSessionInUrl: false } });
  // Assistants the owner uses; anything else gets a warning before Allow.
  const trusted = ['chatgpt.com', 'chat.openai.com', 'openai.com', 'claude.ai', 'claude.com'];

  // A desktop app (such as the ChatGPT Mac app) receives its sign-in on this computer, at a
  // loopback address (RFC 8252); anything else must be https.
  const loopback = host => host === '127.0.0.1' || host === 'localhost' || host === '[::1]';
  const safe = target => target.protocol === 'https:' || (target.protocol === 'http:' && loopback(target.hostname));

  // Only follow redirects Supabase returns to a safe address.
  async function leave(redirect) {
    let target;
    try { target = new URL(redirect); } catch { fail('The app gave an invalid return address.'); return; }
    if (!safe(target)) { fail('The app gave an unsafe return address.'); return; }
    await client.auth.signOut({ scope: 'local' }).catch(() => undefined);
    status(`Returning you to ${target.hostname}…`);
    location.assign(target.href);
  }

  async function loadRequest() {
    status('Checking the request…');
    const { data, error } = await client.auth.oauth.getAuthorizationDetails(id);
    if (error) { status(''); fail('This connection request has expired or is invalid. Start connecting again from your assistant.'); return; }
    if (data.redirect_url) { await leave(data.redirect_url); return; }
    let returnHost = '';
    try { returnHost = new URL(data.redirect_uri).hostname; } catch { /* Shown as given. */ }
    const local = loopback(returnHost);
    $('client-name').textContent = data.client?.name || 'An unnamed app';
    $('client-return').textContent = local ? 'An app on this computer' : returnHost || data.redirect_uri;
    $('client-uri').textContent = data.client?.uri || '—';
    $('account').textContent = data.user?.email ?? '';
    const known = trusted.some(host => returnHost === host || returnHost.endsWith(`.${host}`));
    $('warning').textContent = known ? ''
      : local ? 'This is an app on this computer, such as the ChatGPT desktop app. Only allow it if you just clicked Authenticate or Connect in that app yourself.'
      : `This app returns to ${returnHost || 'an unknown address'}, not ChatGPT or Claude. Only allow it if you're sure you started this connection.`;
    show('warning', !known);
    status('');
    show('sign-in', false);
    show('consent');
  }

  async function decide(allow) {
    fail('');
    for (const button of ['allow', 'deny', 'switch']) $(button).disabled = true;
    const result = allow
      ? await client.auth.oauth.approveAuthorization(id, { skipBrowserRedirect: true })
      : await client.auth.oauth.denyAuthorization(id, { skipBrowserRedirect: true });
    if (result.error || !result.data?.redirect_url) {
      fail('That didn\'t go through. Start connecting again from your assistant.');
      for (const button of ['allow', 'deny', 'switch']) $(button).disabled = false;
      return;
    }
    await leave(result.data.redirect_url);
  }

  $('sign-in').addEventListener('submit', async event => {
    event.preventDefault();
    fail('');
    const button = event.submitter ?? $('sign-in').querySelector('button');
    button.disabled = true;
    status('Signing in…');
    const { error } = await client.auth.signInWithPassword({ email: $('email').value.trim(), password: $('password').value });
    $('password').value = '';
    button.disabled = false;
    if (error) { status(''); fail(error.status === 429 ? 'Too many attempts. Wait a few minutes and try again.' : 'That email and password didn\'t match.'); return; }
    await loadRequest();
  });
  $('allow').addEventListener('click', () => void decide(true));
  $('deny').addEventListener('click', () => void decide(false));
  $('switch').addEventListener('click', async () => {
    await client.auth.signOut({ scope: 'local' }).catch(() => undefined);
    show('consent', false);
    status('');
    show('sign-in');
  });

  (async () => {
    if (!id || !/^[A-Za-z0-9_-]{8,200}$/.test(id)) { status(''); fail('Open this page from your assistant\'s connect button.'); return; }
    if (!url || !key) { status(''); fail('This page isn\'t set up yet.'); return; }
    const { data } = await client.auth.getSession();
    if (data.session) await loadRequest();
    else { status(''); show('sign-in'); $('email').focus(); }
  })().catch(() => { status(''); fail('Something went wrong. Start connecting again from your assistant.'); });
})();
