from flask import Flask, jsonify, request
import sqlite3
import jwt
import datetime
from functools import wraps
import re
import os

# En Vercel el filesystem es de solo lectura excepto /tmp
DB_NAME = '/tmp/vulnerabilidades.db'

app = Flask(__name__)
app.config['SECRET_KEY'] = 'RegistroVulnerabilidadesSecretKey'
Users = {'admin': 'demo123'}

SEVERIDADES = ['baja', 'media', 'alta', 'critica']
ESTADOS     = ['abierta', 'en_revision', 'cerrada', 'mitigada']
PATRON_CVE  = re.compile(r'^CVE-\d{4}-\d{4,}$')


def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilidades (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            titulo       TEXT NOT NULL,
            cve_codigo   TEXT NOT NULL,
            severidad    TEXT NOT NULL
                CHECK (severidad IN ('baja','media','alta','critica')),
            estado       TEXT NOT NULL
                CHECK (estado IN ('abierta','en_revision','cerrada','mitigada')),
            puntaje_cvss REAL NOT NULL
                CHECK (puntaje_cvss >= 0 AND puntaje_cvss <= 10)
        )
    ''')
    conn.commit()
    conn.close()


# Inicializar la DB al arrancar el módulo
init_db()


# ── Autenticación ────────────────────────────────────────────────────────

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({'error': 'Envia un objeto JSON'}), 400
    username = data.get('username')
    clave    = data.get('clave')
    if not isinstance(username, str) or not isinstance(clave, str):
        return jsonify({'error': 'username y clave son obligatorios'}), 400
    if username in Users and Users[username] == clave:
        token = jwt.encode({
            'user': username,
            'exp': datetime.datetime.now(datetime.timezone.utc)
                   + datetime.timedelta(hours=1)
        }, app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'token': token}), 200
    return jsonify({'token': 'Credenciales invalidas'}), 401


def token_required(f):
    @wraps(f)
    def decorador(*args, **kwargs):
        auth   = request.headers.get('Authorization', '')
        partes = auth.split()
        if len(partes) != 2 or partes[0].lower() != 'bearer':
            return jsonify({'error': 'Usa bearer seguido del token'}), 401
        try:
            jwt.decode(partes[1], app.config['SECRET_KEY'],
                       algorithms='HS256',
                       options={'require': ['exp', 'user']})
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expirado'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalido'}), 401
        return f(*args, **kwargs)
    return decorador


# ── Raíz con UI embebida ─────────────────────────────────────────────────

@app.route('/')
def root():
    return '''<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1.0"/>
  <title>API Vulnerabilidades — Tester</title>
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Segoe UI',sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
    header{background:linear-gradient(135deg,#1e293b,#0f172a);border-bottom:1px solid #334155;padding:18px 32px;display:flex;align-items:center;gap:14px}
    header .logo{font-size:22px;font-weight:700;color:#38bdf8}
    header .badge{background:#1e3a5f;color:#7dd3fc;font-size:11px;padding:3px 10px;border-radius:99px;border:1px solid #2563eb55}
    header .token-area{margin-left:auto;display:flex;align-items:center;gap:10px}
    header .token-area span{font-size:12px;color:#94a3b8}
    #token-display{font-size:11px;background:#1e293b;border:1px solid #334155;color:#4ade80;padding:5px 12px;border-radius:6px;max-width:260px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:monospace}
    #token-display.empty{color:#ef4444}
    .layout{display:flex;height:calc(100vh - 63px)}
    .sidebar{width:240px;background:#0f172a;border-right:1px solid #1e293b;overflow-y:auto;padding:16px 0;flex-shrink:0}
    .sidebar-section{padding:6px 16px;font-size:10px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:1px;margin-top:10px}
    .sidebar-item{display:flex;align-items:center;gap:10px;padding:9px 16px;cursor:pointer;font-size:13px;color:#94a3b8;border-left:3px solid transparent;transition:all .15s}
    .sidebar-item:hover{background:#1e293b;color:#e2e8f0}
    .sidebar-item.active{background:#1e3a5f33;border-left-color:#38bdf8;color:#e2e8f0}
    .method-tag{font-size:9px;font-weight:700;padding:2px 6px;border-radius:4px;min-width:36px;text-align:center}
    .GET{background:#14532d;color:#4ade80}.POST{background:#1e3a5f;color:#60a5fa}
    .PUT{background:#431407;color:#fb923c}.DELETE{background:#450a0a;color:#f87171}
    .main{flex:1;display:flex;flex-direction:column;overflow:hidden}
    .panel{display:none;flex-direction:column;height:100%;overflow-y:auto;padding:28px 32px;gap:20px}
    .panel.active{display:flex}
    .panel-title{font-size:18px;font-weight:700;color:#f1f5f9;display:flex;align-items:center;gap:10px}
    .panel-desc{font-size:13px;color:#64748b;margin-top:4px}
    .form-grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
    .field{display:flex;flex-direction:column;gap:6px}
    .field label{font-size:12px;color:#94a3b8;font-weight:600}
    .field input,.field select{background:#1e293b;border:1px solid #334155;color:#e2e8f0;padding:9px 12px;border-radius:8px;font-size:13px;outline:none;transition:border .15s}
    .field input:focus,.field select:focus{border-color:#38bdf8}
    .field select option{background:#1e293b}
    .btn{padding:10px 22px;border-radius:8px;border:none;font-size:13px;font-weight:600;cursor:pointer;transition:opacity .15s,transform .1s;align-self:flex-start}
    .btn:hover{opacity:.85;transform:translateY(-1px)}
    .btn-primary{background:#2563eb;color:#fff}.btn-danger{background:#dc2626;color:#fff}
    .btn-success{background:#16a34a;color:#fff}.btn-warning{background:#d97706;color:#fff}
    .response-box{background:#0a0f1a;border:1px solid #1e293b;border-radius:10px;overflow:hidden}
    .response-header{display:flex;align-items:center;gap:12px;padding:10px 16px;background:#111827;border-bottom:1px solid #1e293b;font-size:12px;color:#64748b}
    .status-badge{padding:3px 10px;border-radius:99px;font-size:12px;font-weight:700}
    .s2xx{background:#14532d;color:#4ade80}.s4xx{background:#450a0a;color:#f87171}.s5xx{background:#431407;color:#fb923c}
    pre{padding:16px;font-size:12px;line-height:1.7;color:#94a3b8;overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-family:monospace}
    .vuln-list{display:flex;flex-direction:column;gap:10px}
    .vuln-card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:14px 18px;display:flex;align-items:center;gap:14px;cursor:pointer;transition:border-color .15s}
    .vuln-card:hover{border-color:#38bdf8}
    .vc-id{font-size:11px;color:#475569;min-width:24px}
    .vc-title{flex:1;font-size:13px;color:#e2e8f0}
    .vc-cve{font-size:11px;color:#7dd3fc;font-family:monospace}
    .sev-pill{font-size:10px;font-weight:700;padding:3px 9px;border-radius:99px}
    .sev-baja{background:#14532d33;color:#4ade80;border:1px solid #14532d}
    .sev-media{background:#78350f33;color:#fbbf24;border:1px solid #78350f}
    .sev-alta{background:#431407;color:#fb923c;border:1px solid #7c2d12}
    .sev-critica{background:#450a0a;color:#f87171;border:1px solid #7f1d1d}
    .est-pill{font-size:10px;padding:3px 9px;border-radius:99px;background:#1e293b;border:1px solid #334155;color:#94a3b8}
    .empty-state{text-align:center;padding:40px;color:#475569;font-size:14px}
    .loader{display:none;width:18px;height:18px;border:2px solid #334155;border-top-color:#38bdf8;border-radius:50%;animation:spin .6s linear infinite}
    @keyframes spin{to{transform:rotate(360deg)}}
    .info-box{background:#1e3a5f22;border:1px solid #1e3a5f;border-radius:8px;padding:12px 16px;font-size:12px;color:#7dd3fc;line-height:1.6}
    .playbook-section{background:#1e293b;border-radius:10px;padding:16px;display:flex;flex-direction:column;gap:10px}
    .playbook-label{font-size:11px;font-weight:700;color:#475569;text-transform:uppercase;letter-spacing:.5px}
    .playbook-value{font-size:13px;color:#e2e8f0}
    code{background:#0f172a;border:1px solid #1e293b;padding:10px 14px;border-radius:6px;display:block;font-size:11px;color:#7dd3fc;font-family:monospace;white-space:pre-wrap;line-height:1.6}
  </style>
</head>
<body>
<header>
  <div class="logo">&#x1F6E1; VulnAPI</div>
  <div class="badge">v1.0 &middot; REST &middot; JWT</div>
  <div class="token-area">
    <span>Token:</span>
    <div id="token-display" class="empty">Sin autenticar</div>
  </div>
</header>
<div class="layout">
  <nav class="sidebar">
    <div class="sidebar-section">Autenticaci&oacute;n</div>
    <div class="sidebar-item active" onclick="show('login',this)"><span class="method-tag POST">POST</span>/login</div>
    <div class="sidebar-section">Vulnerabilidades</div>
    <div class="sidebar-item" onclick="show('listar',this)"><span class="method-tag GET">GET</span>/vulnerabilidades</div>
    <div class="sidebar-item" onclick="show('consultar',this)"><span class="method-tag GET">GET</span>/vulnerabilidades/:id</div>
    <div class="sidebar-item" onclick="show('crear',this)"><span class="method-tag POST">POST</span>/vulnerabilidades</div>
    <div class="sidebar-item" onclick="show('actualizar',this)"><span class="method-tag PUT">PUT</span>/vulnerabilidades/:id</div>
    <div class="sidebar-item" onclick="show('eliminar',this)"><span class="method-tag DELETE">DELETE</span>/vulnerabilidades/:id</div>
    <div class="sidebar-section">Especial</div>
    <div class="sidebar-item" onclick="show('playbook',this)"><span class="method-tag GET">GET</span>/playbook/:id</div>
  </nav>
  <main class="main">

    <!-- LOGIN -->
    <section id="panel-login" class="panel active">
      <div><div class="panel-title"><span class="method-tag POST">POST</span>/login</div>
      <div class="panel-desc">Obt&eacute;n un token JWT. Dura 1 hora.</div></div>
      <div class="info-box">Usuario: <strong>admin</strong> / Clave: <strong>demo123</strong></div>
      <div class="form-grid">
        <div class="field"><label>Username</label><input id="login-user" value="admin"/></div>
        <div class="field"><label>Clave</label><input id="login-pass" value="demo123" type="password"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-primary" onclick="doLogin()">Iniciar sesi&oacute;n</button>
        <div class="loader" id="loader-login"></div>
      </div>
      <div class="response-box">
        <div class="response-header">Respuesta <span id="status-login" class="status-badge"></span></div>
        <pre id="res-login">&#8212; Presiona "Iniciar sesi&oacute;n"</pre>
      </div>
    </section>

    <!-- LISTAR -->
    <section id="panel-listar" class="panel">
      <div><div class="panel-title"><span class="method-tag GET">GET</span>/vulnerabilidades</div>
      <div class="panel-desc">Lista todas. No requiere token.</div></div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-success" onclick="doListar()">Consultar</button>
        <div class="loader" id="loader-listar"></div>
      </div>
      <div id="vuln-cards" class="vuln-list"><div class="empty-state">Presiona "Consultar".</div></div>
      <div class="response-box">
        <div class="response-header">JSON crudo <span id="status-listar" class="status-badge"></span></div>
        <pre id="res-listar">&#8212;</pre>
      </div>
    </section>

    <!-- CONSULTAR -->
    <section id="panel-consultar" class="panel">
      <div><div class="panel-title"><span class="method-tag GET">GET</span>/vulnerabilidades/:id</div>
      <div class="panel-desc">Obtiene una por ID. No requiere token.</div></div>
      <div class="form-grid" style="max-width:300px">
        <div class="field"><label>ID</label><input id="c-id" type="number" value="1" min="1"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-success" onclick="doConsultar()">Consultar</button>
        <div class="loader" id="loader-consultar"></div>
      </div>
      <div class="response-box">
        <div class="response-header">Respuesta <span id="status-consultar" class="status-badge"></span></div>
        <pre id="res-consultar">&#8212;</pre>
      </div>
    </section>

    <!-- CREAR -->
    <section id="panel-crear" class="panel">
      <div><div class="panel-title"><span class="method-tag POST">POST</span>/vulnerabilidades</div>
      <div class="panel-desc">Registra nueva. Requiere token.</div></div>
      <div class="form-grid">
        <div class="field"><label>T&iacute;tulo</label><input id="cr-titulo" value="SQL Injection en login"/></div>
        <div class="field"><label>CVE C&oacute;digo</label><input id="cr-cve" value="CVE-2024-12345"/></div>
        <div class="field"><label>Severidad</label>
          <select id="cr-sev"><option>baja</option><option>media</option><option selected>alta</option><option>critica</option></select>
        </div>
        <div class="field"><label>Estado</label>
          <select id="cr-est"><option selected>abierta</option><option>en_revision</option><option>cerrada</option><option>mitigada</option></select>
        </div>
        <div class="field"><label>Puntaje CVSS (0&#8211;10)</label><input id="cr-cvss" type="number" value="8.1" step="0.1" min="0" max="10"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-primary" onclick="doCrear()">Crear</button>
        <div class="loader" id="loader-crear"></div>
      </div>
      <div class="response-box">
        <div class="response-header">Respuesta <span id="status-crear" class="status-badge"></span></div>
        <pre id="res-crear">&#8212;</pre>
      </div>
    </section>

    <!-- ACTUALIZAR -->
    <section id="panel-actualizar" class="panel">
      <div><div class="panel-title"><span class="method-tag PUT">PUT</span>/vulnerabilidades/:id</div>
      <div class="panel-desc">Actualiza existente. Requiere token.</div></div>
      <div class="form-grid">
        <div class="field"><label>ID</label><input id="up-id" type="number" value="1" min="1"/></div>
        <div class="field"><label>T&iacute;tulo</label><input id="up-titulo" value="SQL Injection actualizado"/></div>
        <div class="field"><label>CVE C&oacute;digo</label><input id="up-cve" value="CVE-2024-12345"/></div>
        <div class="field"><label>Severidad</label>
          <select id="up-sev"><option>baja</option><option>media</option><option>alta</option><option selected>critica</option></select>
        </div>
        <div class="field"><label>Estado</label>
          <select id="up-est"><option>abierta</option><option>en_revision</option><option selected>mitigada</option><option>cerrada</option></select>
        </div>
        <div class="field"><label>Puntaje CVSS</label><input id="up-cvss" type="number" value="9.8" step="0.1" min="0" max="10"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-warning" onclick="doActualizar()">Actualizar</button>
        <div class="loader" id="loader-actualizar"></div>
      </div>
      <div class="response-box">
        <div class="response-header">Respuesta <span id="status-actualizar" class="status-badge"></span></div>
        <pre id="res-actualizar">&#8212;</pre>
      </div>
    </section>

    <!-- ELIMINAR -->
    <section id="panel-eliminar" class="panel">
      <div><div class="panel-title"><span class="method-tag DELETE">DELETE</span>/vulnerabilidades/:id</div>
      <div class="panel-desc">Elimina por ID. Requiere token.</div></div>
      <div class="form-grid" style="max-width:300px">
        <div class="field"><label>ID</label><input id="del-id" type="number" value="1" min="1"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-danger" onclick="doEliminar()">Eliminar</button>
        <div class="loader" id="loader-eliminar"></div>
      </div>
      <div class="response-box">
        <div class="response-header">Respuesta <span id="status-eliminar" class="status-badge"></span></div>
        <pre id="res-eliminar">&#8212;</pre>
      </div>
    </section>

    <!-- PLAYBOOK -->
    <section id="panel-playbook" class="panel">
      <div><div class="panel-title"><span class="method-tag GET">GET</span>/vulnerabilidades/:id/playbook</div>
      <div class="panel-desc">Plan de mitigaci&oacute;n en cloud. Requiere token.</div></div>
      <div class="form-grid" style="max-width:300px">
        <div class="field"><label>ID</label><input id="pb-id" type="number" value="1" min="1"/></div>
      </div>
      <div style="display:flex;gap:12px;align-items:center">
        <button class="btn btn-primary" onclick="doPlaybook()">Generar Playbook</button>
        <div class="loader" id="loader-playbook"></div>
      </div>
      <div id="playbook-render" style="display:none;flex-direction:column;gap:14px">
        <div class="playbook-section">
          <div class="playbook-label">Metadata</div>
          <div id="pb-meta" class="playbook-value"></div>
        </div>
        <div id="pb-plan-wrap" class="playbook-section">
          <div class="playbook-label">Estrategia Cloud</div>
          <div id="pb-estrategia" class="playbook-value"></div>
          <div class="playbook-label" style="margin-top:10px">Script de consola</div>
          <code id="pb-script"></code>
          <div class="playbook-label" style="margin-top:10px">Infraestructura como c&oacute;digo (AWS CLI)</div>
          <code id="pb-aws"></code>
        </div>
        <div class="playbook-section">
          <div class="playbook-label">Estado</div>
          <div id="pb-estado" class="playbook-value"></div>
        </div>
      </div>
      <div class="response-box">
        <div class="response-header">JSON crudo <span id="status-playbook" class="status-badge"></span></div>
        <pre id="res-playbook">&#8212;</pre>
      </div>
    </section>

  </main>
</div>
<script>
  let TOKEN='';
  function show(name,el){
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.sidebar-item').forEach(i=>i.classList.remove('active'));
    document.getElementById('panel-'+name).classList.add('active');
    el.classList.add('active');
  }
  function setStatus(id,code){
    const el=document.getElementById('status-'+id);
    el.textContent=code;
    el.className='status-badge '+(code<300?'s2xx':code<500?'s4xx':'s5xx');
  }
  function setRes(id,data){document.getElementById('res-'+id).textContent=JSON.stringify(data,null,2);}
  function loader(id,on){document.getElementById('loader-'+id).style.display=on?'block':'none';}
  async function call(method,url,body,lid){
    loader(lid,true);
    const opts={method,headers:{'Content-Type':'application/json'}};
    if(TOKEN) opts.headers['Authorization']='Bearer '+TOKEN;
    if(body)  opts.body=JSON.stringify(body);
    try{
      const r=await fetch(url,opts);
      const data=await r.json().catch(()=>({}));
      loader(lid,false);
      return{status:r.status,data};
    }catch(e){
      loader(lid,false);
      return{status:0,data:{error:'No se pudo conectar con la API.'}};
    }
  }
  async function doLogin(){
    const{status,data}=await call('POST','/login',{username:document.getElementById('login-user').value,clave:document.getElementById('login-pass').value},'login');
    setStatus('login',status);setRes('login',data);
    if(data.token&&status===200){
      TOKEN=data.token;
      const d=document.getElementById('token-display');
      d.textContent=TOKEN.substring(0,40)+'…';d.classList.remove('empty');
    }
  }
  async function doListar(){
    const{status,data}=await call('GET','/vulnerabilidades',null,'listar');
    setStatus('listar',status);setRes('listar',data);
    const c=document.getElementById('vuln-cards');
    if(!Array.isArray(data)||data.length===0){c.innerHTML='<div class="empty-state">No hay vulnerabilidades.</div>';return;}
    c.innerHTML=data.map(v=>`<div class="vuln-card" onclick="irA(${v.id})">
      <span class="vc-id">#${v.id}</span>
      <span class="vc-title">${v.titulo}</span>
      <span class="vc-cve">${v.cve_codigo}</span>
      <span class="sev-pill sev-${v.severidad}">${v.severidad}</span>
      <span class="est-pill">${v.estado}</span>
    </div>`).join('');
  }
  function irA(id){
    ['c-id','up-id','del-id','pb-id'].forEach(x=>document.getElementById(x).value=id);
    document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
    document.querySelectorAll('.sidebar-item').forEach(i=>i.classList.remove('active'));
    document.getElementById('panel-consultar').classList.add('active');
    document.querySelectorAll('.sidebar-item')[2].classList.add('active');
    doConsultar();
  }
  async function doConsultar(){
    const id=document.getElementById('c-id').value;
    const{status,data}=await call('GET',`/vulnerabilidades/${id}`,null,'consultar');
    setStatus('consultar',status);setRes('consultar',data);
  }
  async function doCrear(){
    const body={titulo:document.getElementById('cr-titulo').value,cve_codigo:document.getElementById('cr-cve').value,severidad:document.getElementById('cr-sev').value,estado:document.getElementById('cr-est').value,puntaje_cvss:parseFloat(document.getElementById('cr-cvss').value)};
    const{status,data}=await call('POST','/vulnerabilidades',body,'crear');
    setStatus('crear',status);setRes('crear',data);
  }
  async function doActualizar(){
    const id=document.getElementById('up-id').value;
    const body={titulo:document.getElementById('up-titulo').value,cve_codigo:document.getElementById('up-cve').value,severidad:document.getElementById('up-sev').value,estado:document.getElementById('up-est').value,puntaje_cvss:parseFloat(document.getElementById('up-cvss').value)};
    const{status,data}=await call('PUT',`/vulnerabilidades/${id}`,body,'actualizar');
    setStatus('actualizar',status);setRes('actualizar',data);
  }
  async function doEliminar(){
    const id=document.getElementById('del-id').value;
    const{status,data}=await call('DELETE',`/vulnerabilidades/${id}`,null,'eliminar');
    setStatus('eliminar',status);setRes('eliminar',data);
  }
  async function doPlaybook(){
    const id=document.getElementById('pb-id').value;
    const{status,data}=await call('GET',`/vulnerabilidades/${id}/playbook`,null,'playbook');
    setStatus('playbook',status);setRes('playbook',data);
    const render=document.getElementById('playbook-render');
    if(status===200&&data.metadata){
      const m=data.metadata;
      document.getElementById('pb-meta').innerHTML=`<strong>${m.titulo_analizado}</strong> — <span class="vc-cve">${m.identificador}</span><br/>Severidad: <span class="sev-pill sev-${m.severidad_declarada}">${m.severidad_declarada}</span> &nbsp;Estado: <span class="est-pill">${m.estado_actual}</span><br/><small style="color:#475569">Generado: ${new Date(m.fecha_generacion).toLocaleString()}</small>`;
      const wrap=document.getElementById('pb-plan-wrap');
      if(data.plan_mitigacion){
        wrap.style.display='flex';
        document.getElementById('pb-estrategia').textContent=data.plan_mitigacion.estrategia_cloud;
        document.getElementById('pb-script').textContent=data.plan_mitigacion.script_consola_sistema;
        document.getElementById('pb-aws').textContent=data.plan_mitigacion.infraestructura_como_codigo_aws;
      }else{wrap.style.display='none';}
      document.getElementById('pb-estado').textContent=data.estado_playbook;
      render.style.display='flex';
    }else{render.style.display='none';}
  }
</script>
</body>
</html>'''


@app.route('/api')
def api_info():
    return jsonify({'message': 'Api de registro de vulnerabilidades', 'recurso': '/vulnerabilidades'}), 200


# ── Validación ───────────────────────────────────────────────────────────

def validar_vulnerabilidad(data):
    if not isinstance(data, dict):
        return 'Envía un objeto JSON'
    for campo in ('titulo', 'cve_codigo', 'severidad', 'estado'):
        valor = data.get(campo)
        if not isinstance(valor, str) or not valor.strip():
            return f'{campo} debe ser un texto no vacío'
    if not PATRON_CVE.match(data['cve_codigo'].strip()):
        return 'cve_codigo debe tener el formato CVE-AAAA-NNNN (ej: CVE-2024-12345)'
    if data['severidad'].strip() not in SEVERIDADES:
        return 'severidad debe ser una de: ' + ', '.join(SEVERIDADES)
    if data['estado'].strip() not in ESTADOS:
        return 'estado debe ser uno de: ' + ', '.join(ESTADOS)
    puntaje = data.get('puntaje_cvss')
    if type(puntaje) not in (int, float) or puntaje < 0 or puntaje > 10:
        return 'puntaje_cvss debe ser un número entre 0 y 10'
    return None


# ── CRUD ─────────────────────────────────────────────────────────────────

@app.route('/vulnerabilidades', methods=['GET'])
def list_vulnerabilidades():
    conn = get_db()
    filas = conn.execute('SELECT * FROM vulnerabilidades').fetchall()
    conn.close()
    return jsonify([dict(f) for f in filas]), 200


@app.route('/vulnerabilidades/<int:vuln_id>', methods=['GET'])
def get_vulnerabilidad(vuln_id):
    conn = get_db()
    fila = conn.execute('SELECT * FROM vulnerabilidades WHERE id=?', (vuln_id,)).fetchone()
    conn.close()
    if fila is None:
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    return jsonify(dict(fila)), 200


@app.route('/vulnerabilidades', methods=['POST'])
@token_required
def create_vulnerabilidad():
    data  = request.get_json(silent=True)
    error = validar_vulnerabilidad(data)
    if error:
        return jsonify({'error': error}), 400
    conn = get_db()
    cur  = conn.execute(
        'INSERT INTO vulnerabilidades (titulo,cve_codigo,severidad,estado,puntaje_cvss) VALUES (?,?,?,?,?)',
        (data['titulo'].strip(), data['cve_codigo'].strip(),
         data['severidad'].strip(), data['estado'].strip(), data['puntaje_cvss'])
    )
    nuevo_id = cur.lastrowid
    conn.commit(); conn.close()
    return jsonify({'id': nuevo_id, 'message': 'Vulnerabilidad registrada'}), 201


@app.route('/vulnerabilidades/<int:vuln_id>', methods=['PUT'])
@token_required
def update_vulnerabilidad(vuln_id):
    data  = request.get_json(silent=True)
    error = validar_vulnerabilidad(data)
    if error:
        return jsonify({'error': error}), 400
    conn = get_db()
    if conn.execute('SELECT id FROM vulnerabilidades WHERE id=?', (vuln_id,)).fetchone() is None:
        conn.close()
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    conn.execute(
        'UPDATE vulnerabilidades SET titulo=?,cve_codigo=?,severidad=?,estado=?,puntaje_cvss=? WHERE id=?',
        (data['titulo'].strip(), data['cve_codigo'].strip(),
         data['severidad'].strip(), data['estado'].strip(), data['puntaje_cvss'], vuln_id)
    )
    conn.commit(); conn.close()
    return jsonify({'message': 'Vulnerabilidad actualizada'}), 200


@app.route('/vulnerabilidades/<int:vuln_id>', methods=['DELETE'])
@token_required
def delete_vulnerabilidad(vuln_id):
    conn = get_db()
    if conn.execute('SELECT id FROM vulnerabilidades WHERE id=?', (vuln_id,)).fetchone() is None:
        conn.close()
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404
    conn.execute('DELETE FROM vulnerabilidades WHERE id=?', (vuln_id,))
    conn.commit(); conn.close()
    return jsonify({'message': 'Vulnerabilidad eliminada'}), 200


# ── Playbook ─────────────────────────────────────────────────────────────

def generar_comandos_mitigacion(severidad, cve_codigo):
    s = severidad.strip().lower()
    playbooks = {
        'baja': {
            'accion_inmediata': 'Monitoreo preventivo y auditoria de parches periodica.',
            'comando_consola':  'sudo apt-get update && sudo apt-get --just-print upgrade | grep -i security',
            'politica_cloud':   'aws ecr put-image-scanning-configuration --repository-name app-repo --image-scanning-configuration scanOnPush=true'
        },
        'media': {
            'accion_inmediata': 'Restriccion perimetral intermedia y actualizacion programada (max 30 dias).',
            'comando_consola':  'sudo iptables -A INPUT -p tcp --dport 8080 -m limit --limit 25/minute -j ACCEPT\nsudo iptables -A INPUT -p tcp --dport 8080 -j DROP',
            'politica_cloud':   f'# Regla WAF creada preventivamente para mitigar {cve_codigo}'
        },
        'alta': {
            'accion_inmediata': 'Aplicar parches urgentes en la presente ventana de mantenimiento. Limitar accesos.',
            'comando_consola':  'sudo apt-get install --only-upgrade -y openssl libssl-dev',
            'politica_cloud':   'aws ec2 revoke-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 0.0.0.0/0\naws ec2 authorize-security-group-ingress --group-id sg-0123456789abcdef0 --protocol tcp --port 443 --cidr 192.168.1.0/24'
        },
        'critica': {
            'accion_inmediata': 'AISLAMIENTO TOTAL E INMEDIATO DEL RECURSO. Mitigacion de emergencia activa.',
            'comando_consola':  'sudo systemctl stop vulnerable-service && sudo systemctl disable vulnerable-service',
            'politica_cloud':   f'aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 --groups sg-quarantine-isolated-id\n# EMERGENCIA: Alertas enviadas a CloudWatch por {cve_codigo}.'
        }
    }
    return playbooks.get(s, {
        'accion_inmediata': 'Analizar manualmente por el equipo de SecOps.',
        'comando_consola':  '# No hay scripts automatizados para esta severidad.',
        'politica_cloud':   '# Configurar alertas manuales en la consola Cloud.'
    })


@app.route('/vulnerabilidades/<int:vuln_id>/playbook', methods=['GET'])
@token_required
def get_playbook_mitigacion(vuln_id):
    conn = get_db()
    fila = conn.execute(
        'SELECT titulo,cve_codigo,severidad,estado FROM vulnerabilidades WHERE id=?', (vuln_id,)
    ).fetchone()
    conn.close()
    if fila is None:
        return jsonify({'error': 'Vulnerabilidad no encontrada'}), 404

    datos = dict(fila)
    metadata = {
        'vulnerabilidad_id':   vuln_id,
        'titulo_analizado':    datos['titulo'],
        'identificador':       datos['cve_codigo'],
        'severidad_declarada': datos['severidad'],
        'estado_actual':       datos['estado'],
        'fecha_generacion':    datetime.datetime.now(datetime.timezone.utc).isoformat()
    }

    if datos['estado'] in ('cerrada', 'mitigada'):
        return jsonify({
            'metadata':        metadata,
            'plan_mitigacion': None,
            'estado_playbook': 'Sin accion pendiente: la vulnerabilidad esta ' + datos['estado']
        }), 200

    cmd = generar_comandos_mitigacion(datos['severidad'], datos['cve_codigo'])
    return jsonify({
        'metadata': metadata,
        'plan_mitigacion': {
            'estrategia_cloud':               cmd['accion_inmediata'],
            'script_consola_sistema':         cmd['comando_consola'],
            'infraestructura_como_codigo_aws': cmd['politica_cloud']
        },
        'estado_playbook': 'Listo para despliegue / Modo Simulacion'
    }), 200
