(async () => {
  const loginOpts = {
    method: 'POST',
    headers: { 'X-API-Key': 'pk_live_athar_001', 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: 'admin', password: 'admin' })
  };
  for (let i = 0; i < 5; i++) {
    const r = await fetch('https://api.arch-hayder.workers.dev/v1/auth/login', loginOpts);
    console.log('login', i, r.status);
  }
  for (let i = 0; i < 5; i++) {
    const r = await fetch('https://api.arch-hayder.workers.dev/v1/portal/dashboard', { headers: { 'X-API-Key': 'pk_live_athar_001' } });
    console.log('portal', i, r.status);
  }
})();
