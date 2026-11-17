"""Mobilny skaner QR TicketFlow. Uruchamiaj obok app.py i tej samej bazy/sekretu."""
import os, json, hmac, hashlib, sqlite3
from pathlib import Path
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

BASE = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv('TICKETFLOW_DB_PATH', str(BASE / 'ticketflow.sqlite3')))
SECRET_FILE = Path(os.getenv('TICKETFLOW_QR_SECRET_FILE', str(BASE / 'ticketflow_qr_secret.key')))
PIN = os.getenv('TICKETFLOW_SCANNER_PIN', '')

def secret():
    env = os.getenv('TICKETFLOW_QR_SECRET', '').strip()
    if env: return env.encode()
    if not SECRET_FILE.exists(): raise RuntimeError('Brak ticketflow_qr_secret.key. Skopiuj sekret z głównej aplikacji lub ustaw TICKETFLOW_QR_SECRET.')
    return SECRET_FILE.read_bytes()

def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('PRAGMA foreign_keys=ON')
    return con

def validate(text):
    try: envelope = json.loads((text or '').strip())
    except Exception: envelope = None
    if not isinstance(envelope, dict):
        with db() as con:
            row = con.execute('''SELECT t.*, e.name event_name, e.event_date, u.full_name promoter_name FROM tickets t JOIN events e ON e.id=t.event_id LEFT JOIN users u ON u.id=t.promoter_id WHERE t.code=?''', ((text or '').strip(),)).fetchone()
        return (dict(row), None) if row else (None, 'Nie rozpoznano kodu QR.')
    payload, signature = envelope.get('ticket'), envelope.get('signature')
    if not isinstance(payload, dict) or not isinstance(signature, str) or payload.get('type') != 'ticketflow_ticket': return None, 'To nie jest bilet TicketFlow.'
    raw = json.dumps(payload, ensure_ascii=False, separators=(',', ':'), sort_keys=True)
    if not hmac.compare_digest(signature, hmac.new(secret(), raw.encode(), hashlib.sha256).hexdigest()): return None, 'Nieprawidłowy podpis QR.'
    try: ticket_id = int(payload['ticket_id'])
    except (KeyError, TypeError, ValueError): return None, 'Nieprawidłowy identyfikator biletu.'
    with db() as con:
        row = con.execute('''SELECT t.*, e.name event_name, e.event_date, u.full_name promoter_name FROM tickets t JOIN events e ON e.id=t.event_id LEFT JOIN users u ON u.id=t.promoter_id WHERE t.id=?''', (ticket_id,)).fetchone()
    if not row: return None, 'Nie znaleziono biletu w bazie.'
    t = dict(row)
    fields = {'event':t['event_name'],'event_date':t['event_date'],'buyer_name':t['buyer_name'],'buyer_email':t['buyer_email'] or '', 'price':round(float(t['price']),2),'created_at':t['created_at']}
    if any(payload.get(k) != v for k,v in fields.items()): return None, 'Dane QR nie zgadzają się z bazą.'
    return t, None

PAGE = r'''<!doctype html><html lang="pl"><head><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"><meta charset="utf-8"><title>TicketFlow — Skaner</title><script src="https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js"></script><style>
*{box-sizing:border-box}body{margin:0;background:#050505;color:#fff;font:16px system-ui,-apple-system,sans-serif}main{max-width:560px;margin:auto;padding:20px 16px 40px}h1{font-size:28px;margin:8px 0}p{color:#cfcfcf}.panel{background:#111;border:1px solid #333;border-radius:16px;padding:16px;margin:16px 0}input,button{width:100%;font:inherit;padding:14px;border-radius:10px;margin-top:8px}input{background:#050505;color:white;border:1px solid #555}button{border:0;background:#fff;color:#000;font-weight:700;cursor:pointer}button.secondary{background:#252525;color:white;border:1px solid #555}#reader{width:100%;overflow:hidden;border-radius:12px}#result{white-space:pre-wrap;line-height:1.5}.good{color:#78f0a2}.bad{color:#ff8c8c}.warn{color:#ffd36e}.small{font-size:13px;color:#aaa}</style></head><body><main><h1>🎟️ TicketFlow</h1><p>Mobilny skaner kodów QR</p><div class="panel"><label for="pin">PIN obsługi</label><input id="pin" type="password" inputmode="numeric" autocomplete="current-password" placeholder="Wpisz PIN skanera"><p class="small">Ustaw PIN przez zmienną TICKETFLOW_SCANNER_PIN na serwerze.</p><button onclick="startScan()">Uruchom aparat</button><button class="secondary" onclick="stopScan()">Zatrzymaj aparat</button><div id="reader" style="margin-top:14px"></div></div><div class="panel"><label for="manual">Lub wklej treść QR</label><input id="manual" placeholder="Treść kodu QR"><button onclick="checkQr(document.getElementById('manual').value)">Sprawdź bilet</button></div><div class="panel"><div id="result">Wynik skanowania pojawi się tutaj.</div><div id="actions"></div></div></main><script>
let scanner=null,lastTicket=null; const pin=()=>document.getElementById('pin').value;
async function startScan(){if(!pin()){alert('Wpisz PIN obsługi.');return}if(!window.Html5Qrcode){alert('Nie udało się załadować skanera. Sprawdź internet.');return}try{if(!scanner)scanner=new Html5Qrcode('reader');await scanner.start({facingMode:'environment'},{fps:10,qrbox:{width:260,height:260}},txt=>{stopScan();checkQr(txt)},()=>{});}catch(e){document.getElementById('result').textContent='Nie można uruchomić aparatu. Otwórz stronę przez HTTPS i zezwól na dostęp do aparatu. '+e}}
async function stopScan(){if(scanner){try{if(scanner.isScanning)await scanner.stop()}catch(e){}}}
async function checkQr(text){document.getElementById('result').textContent='Sprawdzanie…';document.getElementById('actions').innerHTML='';try{let r=await fetch('/api/check',{method:'POST',headers:{'Content-Type':'application/json','X-Scanner-Pin':pin()},body:JSON.stringify({qr:text})});let d=await r.json();lastTicket=d.ticket||null;document.getElementById('result').innerHTML='';let div=document.createElement('div');div.className=d.ok?(d.ticket.status==='used'?'warn':'good'):'bad';div.textContent=d.message+(d.ticket?'\n\nWydarzenie: '+d.ticket.event_name+'\nData: '+d.ticket.event_date+'\nUczestnik: '+d.ticket.buyer_name+'\nE-mail: '+(d.ticket.buyer_email||'—')+'\nCena: '+d.ticket.price+'\nStatus: '+d.ticket.status:'');document.getElementById('result').appendChild(div);if(d.ok&&d.ticket.status==='valid'){let b=document.createElement('button');b.textContent='Oznacz bilet jako wykorzystany';b.onclick=()=>useTicket(d.ticket.id);document.getElementById('actions').appendChild(b)}}catch(e){document.getElementById('result').textContent='Błąd połączenia z serwerem.'}}
async function useTicket(id){let r=await fetch('/api/use',{method:'POST',headers:{'Content-Type':'application/json','X-Scanner-Pin':pin()},body:JSON.stringify({ticket_id:id})});let d=await r.json();document.getElementById('result').textContent=d.message;document.getElementById('actions').innerHTML=''}
</script></body></html>'''

class Handler(BaseHTTPRequestHandler):
    def _json(self, status, data):
        body=json.dumps(data,ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_GET(self):
        if urlparse(self.path).path != '/': self._json(404, {'message':'Nie znaleziono'}); return
        body=PAGE.encode('utf-8'); self.send_response(200); self.send_header('Content-Type','text/html; charset=utf-8'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def do_POST(self):
        if not PIN or not hmac.compare_digest(self.headers.get('X-Scanner-Pin',''), PIN): self._json(401, {'ok':False,'message':'Brak dostępu. Sprawdź PIN skanera.'}); return
        try: data=json.loads(self.rfile.read(int(self.headers.get('Content-Length','0'))) or b'{}')
        except Exception: data={}
        path=urlparse(self.path).path
        if path == '/api/check':
            ticket,error=validate(data.get('qr',''))
            if error: self._json(200, {'ok':False,'message':error}); return
            if ticket['status']=='cancelled': self._json(200, {'ok':False,'message':'Bilet anulowany.','ticket':ticket}); return
            if ticket['status']=='used': self._json(200, {'ok':True,'message':'Bilet został już wykorzystany!','ticket':ticket}); return
            self._json(200, {'ok':True,'message':'Bilet ważny — można wpuścić uczestnika.','ticket':ticket}); return
        if path == '/api/use':
            try: tid=int(data.get('ticket_id'))
            except (TypeError,ValueError): self._json(400, {'message':'Nieprawidłowy numer biletu.'}); return
            with db() as con: cur=con.execute("UPDATE tickets SET status='used', checked_at=?, checked_by=NULL WHERE id=? AND status='valid'",(datetime.now().isoformat(timespec='seconds'),tid))
            if cur.rowcount: self._json(200, {'message':'Bilet oznaczony jako wykorzystany.'})
            else: self._json(409, {'message':'Bilet nie istnieje albo został już wykorzystany.'})
            return
        self._json(404, {'message':'Nie znaleziono'})
    def log_message(self, format, *args): pass

if __name__=='__main__':
    if not PIN: raise SystemExit('Ustaw TICKETFLOW_SCANNER_PIN przed uruchomieniem skanera.')
    server=ThreadingHTTPServer(('0.0.0.0',int(os.getenv('PORT','5000'))),Handler)
    print('TicketFlow Scanner działa na porcie', os.getenv('PORT','5000'))
    server.serve_forever()
