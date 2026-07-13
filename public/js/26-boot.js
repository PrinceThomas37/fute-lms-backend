// ── Boot ───────────────────────────────────────
if(STATE.token&&STATE.user){STATE.page='dashboard';loadAppData();}else{STATE.page='login';render();}
