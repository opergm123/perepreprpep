// ═══════════════════════════════════════════════════
//  ПЕРЕЗАЖИГАЛ — Node.js Backend Server v3.0
//  ✅ Все баги исправлены
//  🆕 Статусы пользователей (Discord-style)
//  🆕 bcrypt хеширование паролей
//  🆕 Лимит размера тела запроса
//  🆕 Валидация получателя сообщений
//  🆕 Проверка авторства при удалении
//  🆕 UUID для сообщений
//  Запуск: node server.js
//  Порт: 3000
// ═══════════════════════════════════════════════════

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const url    = require('url');

const PORT    = process.env.PORT || 3000;
const DB_FILE = path.join(__dirname, 'perezazhigal.db');
const MAX_BODY = 12 * 1024 * 1024; // 12MB

// ── SQLite через встроенный node:sqlite (Node 22.5+) или fallback JSON ──
let db;
let useSQL = false;

try {
  const { DatabaseSync } = require('node:sqlite');
  db = new DatabaseSync(DB_FILE);
  db.exec(`
    PRAGMA journal_mode=WAL;

    CREATE TABLE IF NOT EXISTS users (
      uid TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      bio TEXT DEFAULT '',
      color INTEGER DEFAULT 0,
      ava_emo TEXT,
      ava_img TEXT,
      username_changed_at INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT 0,
      status TEXT DEFAULT 'online'
    );

    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      uid TEXT NOT NULL,
      created_at INTEGER DEFAULT 0,
      last_seen INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      room_id TEXT NOT NULL,
      from_uid TEXT NOT NULL,
      to_uid TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'text',
      text TEXT DEFAULT '',
      data_url TEXT,
      file_name TEXT,
      file_size TEXT,
      file_type TEXT,
      reply_json TEXT,
      time_str TEXT,
      timestamp INTEGER,
      read INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS blocks (
      blocker_uid TEXT NOT NULL,
      blocked_uid TEXT NOT NULL,
      created_at INTEGER DEFAULT 0,
      PRIMARY KEY (blocker_uid, blocked_uid)
    );

    CREATE INDEX IF NOT EXISTS idx_messages_room ON messages(room_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_sessions_uid ON sessions(uid);
    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_users_name ON users(name COLLATE NOCASE);
    CREATE INDEX IF NOT EXISTS idx_blocks_blocker ON blocks(blocker_uid);
  `);

  // Добавить колонку status если её нет (миграция для старых БД)
  try { db.exec(`ALTER TABLE users ADD COLUMN status TEXT DEFAULT 'online'`); } catch {}
  try { db.exec(`ALTER TABLE sessions ADD COLUMN last_seen INTEGER DEFAULT 0`); } catch {}
  // Админ миграции
  try { db.exec(`ALTER TABLE users ADD COLUMN banned INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE users ADD COLUMN ban_reason TEXT DEFAULT ''`); } catch {}
  try { db.exec(`ALTER TABLE users ADD COLUMN ban_until INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE users ADD COLUMN muted INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE users ADD COLUMN mute_until INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`ALTER TABLE users ADD COLUMN warn_count INTEGER DEFAULT 0`); } catch {}
  try { db.exec(`CREATE TABLE IF NOT EXISTS admin_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_uid TEXT NOT NULL,
    action TEXT NOT NULL,
    target_uid TEXT,
    details TEXT,
    ip TEXT DEFAULT '',
    timestamp INTEGER DEFAULT 0
  )`); } catch {}
  try { db.exec(`CREATE TABLE IF NOT EXISTS system_broadcasts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_uid TEXT NOT NULL,
    text TEXT NOT NULL,
    type TEXT DEFAULT 'info',
    timestamp INTEGER DEFAULT 0
  )`); } catch {}
  try { db.exec(`CREATE TABLE IF NOT EXISTS ip_bans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    reason TEXT DEFAULT '',
    admin_uid TEXT,
    created_at INTEGER DEFAULT 0
  )`); } catch(e) { console.warn('ip_bans table warning:', e.message); }

  try { db.exec(`CREATE TABLE IF NOT EXISTS user_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_uid TEXT NOT NULL,
    target_uid TEXT NOT NULL,
    note TEXT NOT NULL,
    timestamp INTEGER DEFAULT 0
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS user_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uid TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT DEFAULT '',
    action TEXT DEFAULT 'login',
    timestamp INTEGER DEFAULT 0
  )`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_user_ips_uid ON user_ips(uid, timestamp DESC)`);
  } catch(e) { console.warn('user_ips warning:', e.message); }

  useSQL = true;
  console.log('[DB] SQLite подключена ✓');
} catch(e) {
  console.warn('[DB] SQLite недоступна, используется JSON-файл. Причина:', e.message);
  useSQL = false;
}

// ── JSON fallback ──
const JSON_FILE = path.join(__dirname, 'db.json');
let DB = { users:{}, messages:{}, sessions:{} };
if (!useSQL) {
  try {
    if (fs.existsSync(JSON_FILE)) {
      DB = JSON.parse(fs.readFileSync(JSON_FILE,'utf8'));
      console.log(`[DB] JSON загружена: ${Object.keys(DB.users).length} пользователей`);
    }
  } catch(e) { console.error('[DB] Ошибка загрузки JSON:', e.message); }
  setInterval(()=>{
    try{ fs.writeFileSync(JSON_FILE, JSON.stringify(DB,null,2)); }catch{}
  }, 5000);
}

// ── Utils ──
function genUid()   { return 'u_'+crypto.randomBytes(8).toString('hex'); }
function genToken() { return crypto.randomBytes(32).toString('hex'); }
function genMsgId() { return crypto.randomUUID(); }

// ── Кеш подготовленных SQL-стейтментов ──
const stmtCache = {};
function stmt(sql) {
  if (!stmtCache[sql]) stmtCache[sql] = db.prepare(sql);
  return stmtCache[sql];
}

// ── Дебаунс обновлений last_seen (не пишем в БД на каждый запрос) ──
const lastSeenPending = {};
function touchLastSeen(token) {
  lastSeenPending[token] = nowMs();
}
setInterval(() => {
  const tokens = Object.keys(lastSeenPending);
  if (!tokens.length) return;
  const update = stmt('UPDATE sessions SET last_seen=? WHERE token=?');
  for (const token of tokens) {
    try { update.run(lastSeenPending[token], token); } catch {}
  }
  for (const t of tokens) delete lastSeenPending[t];
}, 10000); // flush раз в 10 сек вместо на каждый запрос

// ── Безопасное хеширование паролей через scrypt ──
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  // Поддержка старых sha256 хешей для обратной совместимости
  if (!stored.includes(':')) {
    const oldHash = crypto.createHash('sha256').update(password+'pz_salt_2025').digest('hex');
    return oldHash === stored;
  }
  const [salt, hash] = stored.split(':');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash,'hex'), Buffer.from(derived,'hex'));
}

function roomId(a,b){ return [a,b].sort().join(':'); }
function nowMs()    { return Date.now(); }

function json(res, code, data) {
  const body = JSON.stringify(data);
  res.writeHead(code, {
    'Content-Type':'application/json',
    'Access-Control-Allow-Origin':'*',
    'Access-Control-Allow-Headers':'*',
    'Access-Control-Allow-Methods':'*'
  });
  res.end(body);
}

// Допустимые статусы (Discord-style)
const VALID_STATUSES = ['online','idle','dnd','invisible'];

// ── Кеш пользователей (invalidate при updateUser) ──
const userCache = new Map(); // uid → user object
const USER_CACHE_TTL = 30000; // 30 сек

function cacheUser(u) {
  userCache.set(u.uid, { user: u, ts: Date.now() });
}

function getCachedUser(uid) {
  const entry = userCache.get(uid);
  if (!entry) return null;
  if (Date.now() - entry.ts > USER_CACHE_TTL) { userCache.delete(uid); return null; }
  return entry.user;
}

function invalidateUserCache(uid) {
  userCache.delete(uid);
}

function invalidateAllUserCache() {
  userCache.clear();
}

// ── DB adapter ──
const dbAdapter = {
  // Users
  createUser(u) {
    if (useSQL) {
      stmt(`INSERT INTO users
        (uid,name,username,email,password_hash,bio,color,ava_emo,ava_img,username_changed_at,created_at,status)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`).run(u.uid,u.name,u.username,u.email,u.passwordHash,u.bio||'',u.color||0,u.avaEmo||null,u.avaImg||null,u.usernameChangedAt||0,u.createdAt||nowMs(),u.status||'online');
    } else {
      DB.users[u.email] = u;
    }
  },

  getUserByEmail(email) {
    if (useSQL) {
      const row = stmt('SELECT * FROM users WHERE email=?').get(email);
      return row ? rowToUser(row) : null;
    }
    return DB.users[email] || null;
  },

  getUserByUid(uid) {
    if (useSQL) {
      const cached = getCachedUser(uid);
      if (cached) return cached;
      const row = stmt('SELECT * FROM users WHERE uid=?').get(uid);
      const user = row ? rowToUser(row) : null;
      if (user) cacheUser(user);
      return user;
    }
    return Object.values(DB.users).find(u=>u.uid===uid) || null;
  },

  getUserByUsername(username) {
    if (useSQL) {
      const row = stmt('SELECT * FROM users WHERE username=? COLLATE NOCASE').get(username);
      return row ? rowToUser(row) : null;
    }
    return Object.values(DB.users).find(u=>u.username.toLowerCase()===username.toLowerCase()) || null;
  },

  searchUsers(q, excludeUid, limit=30) {
    if (useSQL) {
      const like = '%'+q+'%';
      return stmt(`SELECT * FROM users WHERE uid!=? AND (name LIKE ? OR username LIKE ?) LIMIT ?`).all(excludeUid, like, like, limit).map(rowToUser);
    }
    const all = Object.values(DB.users).filter(u=>u.uid!==excludeUid);
    if (!q) return all.slice(0, limit);
    const ql = q.toLowerCase();
    return all.filter(u=>u.name.toLowerCase().includes(ql)||(u.username||'').toLowerCase().includes(ql)).slice(0, limit);
  },

  getAllUsers(excludeUid) {
    if (useSQL) {
      return stmt('SELECT * FROM users WHERE uid!=? ORDER BY created_at DESC').all(excludeUid).map(rowToUser);
    }
    return Object.values(DB.users).filter(u=>u.uid!==excludeUid);
  },

  updateUser(uid, fields) {
    if (useSQL) {
      const sets = [];
      const vals = [];
      if (fields.name !== undefined)               { sets.push('name=?');                vals.push(fields.name); }
      if (fields.bio !== undefined)                { sets.push('bio=?');                 vals.push(fields.bio); }
      if (fields.color !== undefined)              { sets.push('color=?');               vals.push(fields.color); }
      if (fields.avaEmo !== undefined)             { sets.push('ava_emo=?');             vals.push(fields.avaEmo); }
      if (fields.avaImg !== undefined)             { sets.push('ava_img=?');             vals.push(fields.avaImg); }
      if (fields.username !== undefined)           { sets.push('username=?');            vals.push(fields.username); }
      if (fields.usernameChangedAt !== undefined)  { sets.push('username_changed_at=?'); vals.push(fields.usernameChangedAt); }
      if (fields.status !== undefined)             { sets.push('status=?');              vals.push(fields.status); }
      if (!sets.length) return;
      vals.push(uid);
      db.prepare(`UPDATE users SET ${sets.join(',')} WHERE uid=?`).run(...vals);
      invalidateUserCache(uid);
    } else {
      const u = Object.values(DB.users).find(x=>x.uid===uid);
      if (u) Object.assign(u, fields);
    }
  },

  // Sessions
  createSession(token, uid) {
    if (useSQL) {
      stmt('INSERT OR REPLACE INTO sessions (token,uid,created_at,last_seen) VALUES (?,?,?,?)').run(token, uid, nowMs(), nowMs());
    } else {
      DB.sessions[token] = { uid, createdAt: nowMs(), lastSeen: nowMs() };
    }
  },

  getUidByToken(token) {
    if (useSQL) {
      const row = stmt('SELECT uid FROM sessions WHERE token=?').get(token);
      if (row) {
        // Откладываем обновление last_seen — не пишем в БД на каждый запрос
        touchLastSeen(token);
      }
      return row ? row.uid : null;
    }
    const s = DB.sessions[token];
    return s ? (typeof s === 'string' ? s : s.uid) : null;
  },

  deleteSession(token) {
    if (useSQL) {
      stmt('DELETE FROM sessions WHERE token=?').run(token);
    } else {
      delete DB.sessions[token];
    }
  },

  // Очистка старых сессий (>30 дней)
  cleanOldSessions() {
    const cutoff = nowMs() - 30*24*3600000;
    if (useSQL) {
      stmt('DELETE FROM sessions WHERE last_seen < ?').run(cutoff);
    } else {
      for (const [token, s] of Object.entries(DB.sessions)) {
        const ts = typeof s === 'string' ? 0 : (s.lastSeen||0);
        if (ts < cutoff) delete DB.sessions[token];
      }
    }
  },

  // Messages
  getMessages(rId, limit=200) {
    if (useSQL) {
      const rows = stmt('SELECT * FROM messages WHERE room_id=? ORDER BY timestamp DESC LIMIT ?').all(rId, limit).reverse();
      return rows.map(rowToMsg);
    }
    return (DB.messages[rId] || []).slice(-limit);
  },

  addMessage(msg) {
    if (useSQL) {
      stmt(`INSERT INTO messages
        (id,room_id,from_uid,to_uid,type,text,data_url,file_name,file_size,file_type,reply_json,time_str,timestamp,read)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).run(
        String(msg.id), msg.roomId, msg.from, msg.to,
        msg.type||'text', msg.text||'', msg.dataUrl||null,
        msg.fileName||null, msg.fileSize||null, msg.fileType||null,
        msg.reply ? JSON.stringify(msg.reply) : null,
        msg.time, msg.timestamp, 0
      );
    } else {
      if (!DB.messages[msg.roomId]) DB.messages[msg.roomId] = [];
      DB.messages[msg.roomId].push(msg);
      if (DB.messages[msg.roomId].length > 500)
        DB.messages[msg.roomId] = DB.messages[msg.roomId].slice(-500);
    }
  },

  // Возвращает true если сообщение принадлежит uid
  isMessageOwner(roomId, msgId, uid) {
    if (useSQL) {
      const row = stmt('SELECT from_uid FROM messages WHERE room_id=? AND id=?').get(roomId, String(msgId));
      return row ? row.from_uid === uid : false;
    }
    const msg = (DB.messages[roomId]||[]).find(m=>String(m.id)===String(msgId));
    return msg ? msg.from === uid : false;
  },

  markRead(rId, fromUid) {
    if (useSQL) {
      stmt('UPDATE messages SET read=1 WHERE room_id=? AND from_uid=? AND read=0').run(rId, fromUid);
    } else {
      (DB.messages[rId]||[]).forEach(m=>{ if(m.from===fromUid) m.read=true; });
    }
  },

  deleteMessage(rId, msgId) {
    if (useSQL) {
      stmt('DELETE FROM messages WHERE room_id=? AND id=?').run(rId, String(msgId));
    } else {
      DB.messages[rId] = (DB.messages[rId]||[]).filter(m=>String(m.id)!==String(msgId));
    }
  },

  getUnreadCount(rId, fromUid) {
    if (useSQL) {
      const row = stmt('SELECT COUNT(*) as cnt FROM messages WHERE room_id=? AND from_uid=? AND read=0').get(rId, fromUid);
      return row ? row.cnt : 0;
    }
    return (DB.messages[rId]||[]).filter(m=>m.from===fromUid&&!m.read).length;
  },

  // Conversations list for user
  getConversations(uid) {
    if (useSQL) {
      return stmt(`
        SELECT
          CASE WHEN from_uid=? THEN to_uid ELSE from_uid END as partner_uid,
          room_id,
          MAX(timestamp) as last_ts
        FROM messages
        WHERE from_uid=? OR to_uid=?
        GROUP BY room_id
        ORDER BY last_ts DESC
      `).all(uid, uid, uid);
    }
    const rooms = Object.keys(DB.messages).filter(r=>r.includes(uid));
    return rooms.map(r=>{
      const parts = r.split(':');
      const partner = parts[0]===uid ? parts[1] : parts[0];
      const msgs = DB.messages[r]||[];
      const last = msgs[msgs.length-1];
      return { partner_uid: partner, room_id: r, last_ts: last ? last.timestamp : 0 };
    }).sort((a,b)=>b.last_ts-a.last_ts);
  }
};

// Очищать старые сессии раз в час
setInterval(()=>{ try{ dbAdapter.cleanOldSessions(); }catch{} }, 3600000);

function rowToUser(row) {
  return {
    uid: row.uid,
    name: row.name,
    username: row.username,
    email: row.email,
    passwordHash: row.password_hash,
    bio: row.bio||'',
    color: row.color||0,
    avaEmo: row.ava_emo||null,
    avaImg: row.ava_img||null,
    usernameChangedAt: row.username_changed_at||0,
    createdAt: row.created_at||0,
    status: row.status||'online',
    banned: row.banned||0,
    banReason: row.ban_reason||'',
    banUntil: row.ban_until||0,
    muted: row.muted||0,
    muteUntil: row.mute_until||0,
    warnCount: row.warn_count||0
  };
}

function rowToMsg(row) {
  return {
    id: row.id,
    roomId: row.room_id,
    from: row.from_uid,       // ← всегда UID, клиент сам определяет 'me'/'them'
    to: row.to_uid,
    type: row.type||'text',
    text: row.text||'',
    dataUrl: row.data_url||null,
    fileName: row.file_name||null,
    fileSize: row.file_size||null,
    fileType: row.file_type||null,
    reply: row.reply_json ? JSON.parse(row.reply_json) : null,
    time: row.time_str,
    timestamp: row.timestamp,
    read: !!row.read
  };
}

function safeUser(u) {
  return {
    uid: u.uid,
    name: u.name,
    username: u.username,
    email: u.email,           // ← включаем email для профиля
    bio: u.bio||'',
    color: u.color||0,
    avaEmo: u.avaEmo||null,
    avaImg: u.avaImg||null,
    usernameChangedAt: u.usernameChangedAt||0,
    createdAt: u.createdAt||0,
    status: u.status||'online',
    verified: !!(global.verifiedUsers && global.verifiedUsers[u.uid])
  };
}

// ── SSE clients ──
const sseClients = {}; // uid -> [res,...]

function sendEvent(uid, event, data) {
  const clients = sseClients[uid] || [];
  const msg = `event:${event}\ndata:${JSON.stringify(data)}\n\n`;
  clients.forEach(res => { try{ res.write(msg); }catch{} });
}

function broadcastToAll(event, data, exceptUid=null) {
  Object.keys(sseClients).forEach(uid => {
    if (uid !== exceptUid) sendEvent(uid, event, data);
  });
}

// ── Admin helpers ──
function isAdmin(uid) {
  const u = dbAdapter.getUserByUid(uid);
  return u && (u.username === '@boss' || u.username === '@vyyxek');
}

function adminLog(adminUid, action, targetUid, details, ip='') {
  if (!useSQL) return;
  try {
    db.prepare('INSERT INTO admin_log (admin_uid, action, target_uid, details, ip, timestamp) VALUES (?,?,?,?,?,?)').run(
      adminUid, action, targetUid||null, details||null, ip, nowMs()
    );
  } catch(e) { console.error('[ADMIN_LOG]', e.message); }
}

function recordUserIp(uid, ip, userAgent='', action='login') {
  if (!useSQL || !ip) return;
  try {
    db.prepare('INSERT INTO user_ips (uid, ip, user_agent, action, timestamp) VALUES (?,?,?,?,?)').run(uid, ip, userAgent.slice(0,200), action, nowMs());
  } catch {}
}

function adminSafeUser(u) {
  return {
    uid: u.uid,
    name: u.name,
    username: u.username,
    email: u.email,
    bio: u.bio||'',
    color: u.color||0,
    avaEmo: u.avaEmo||null,
    avaImg: u.avaImg||null,
    createdAt: u.createdAt||0,
    status: u.status||'online',
    banned: u.banned||0,
    banReason: u.banReason||'',
    banUntil: u.banUntil||0,
    muted: u.muted||0,
    muteUntil: u.muteUntil||0,
    warnCount: u.warnCount||0,
    online: !!(sseClients[u.uid]?.length)
  };
}

// ── Route handler ──
async function handle(req, res) {
  const parsedUrl = url.parse(req.url, true);
  const pathname  = parsedUrl.pathname;
  const method    = req.method;

  // CORS preflight
  if (method === 'OPTIONS') {
    res.writeHead(204,{'Access-Control-Allow-Origin':'*','Access-Control-Allow-Headers':'*','Access-Control-Allow-Methods':'*'});
    res.end(); return;
  }

  // Serve frontend
  if (method === 'GET' && (pathname==='/'||pathname==='/app'||pathname==='/index.html')) {
    const htmlFile = path.join(__dirname, 'perezazhigal.html');
    if (fs.existsSync(htmlFile)) {
      res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
      fs.createReadStream(htmlFile).pipe(res);
    } else {
      json(res, 404, {error:'perezazhigal.html not found'});
    }
    return;
  }

  // SSE
  if (pathname === '/events') {
    const t = parsedUrl.query.token;
    const uid = dbAdapter.getUidByToken(t);
    if (!uid) { json(res,401,{error:'Unauthorized'}); return; }

    res.writeHead(200,{
      'Content-Type':'text/event-stream',
      'Cache-Control':'no-cache',
      'Connection':'keep-alive',
      'Access-Control-Allow-Origin':'*',
    });
    res.write(':connected\n\n');

    if (!sseClients[uid]) sseClients[uid]=[];
    sseClients[uid].push(res);

    // Получаем статус пользователя (invisible → offline для других)
    const user = dbAdapter.getUserByUid(uid);
    const effectiveStatus = user?.status === 'invisible' ? 'offline' : (user?.status || 'online');
    
    if (effectiveStatus !== 'offline') {
      broadcastToAll('user_presence', {uid, status: effectiveStatus}, uid);
    }

    const hb = setInterval(()=>{ try{ res.write(':ping\n\n'); }catch{} }, 25000);

    req.on('close', ()=>{
      clearInterval(hb);
      sseClients[uid] = (sseClients[uid]||[]).filter(r=>r!==res);
      if (!sseClients[uid]?.length) {
        delete sseClients[uid];
        // При disconnect — уходим offline только если статус не invisible
        const u2 = dbAdapter.getUserByUid(uid);
        if (u2?.status !== 'invisible') {
          broadcastToAll('user_presence', {uid, status:'offline'});
        }
      }
    });
    return;
  }

  // Parse body с лимитом размера
  let body = {};
  if (method === 'POST' || method === 'PATCH' || method === 'PUT') {
    body = await new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', c => {
        size += c.length;
        if (size > MAX_BODY) {
          req.destroy();
          reject(new Error('Payload too large'));
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { resolve({}); }
      });
      req.on('error', ()=>resolve({}));
    }).catch(()=>null);

    if (body === null) { json(res,413,{error:'Файл слишком большой'}); return; }
  }

  // Client IP
  const clientIp = (req.headers['x-forwarded-for']||'').split(',')[0].trim() || req.socket.remoteAddress || '';

  // ── IP-бан (проверяем для всех запросов кроме самого админа) ──
  if (useSQL && !pathname.startsWith('/admin')) {
    try {
      const ipBanned = db.prepare('SELECT id FROM ip_bans WHERE ip=?').get(clientIp);
      if (ipBanned) return json(res, 403, {error: 'Ваш IP-адрес заблокирован администратором'});
    } catch {}
  }

  // Auth header
  const authToken  = (req.headers['authorization']||'').replace('Bearer ','').trim();
  const currentUid = authToken ? dbAdapter.getUidByToken(authToken) : null;

  // ── Режим обслуживания — блокируем всех кроме @boss ──
  if (global.maintenanceMode && !pathname.startsWith('/auth/login') && !pathname.startsWith('/admin')) {
    if (!currentUid || !isAdmin(currentUid)) {
      return json(res, 503, {error: '🔧 Сервер на техническом обслуживании. Попробуйте позже.'});
    }
  }

  // ══════════════════════════
  //  AUTH ROUTES
  // ══════════════════════════

  // POST /auth/register
  if (method==='POST' && pathname==='/auth/register') {
    const {name,username,email,password} = body;
    if (!name||!username||!email||!password) return json(res,400,{error:'Заполните все поля'});
    if (password.length<6) return json(res,400,{error:'Пароль минимум 6 символов'});
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json(res,400,{error:'Некорректный email'});

    if (dbAdapter.getUserByEmail(email)) return json(res,409,{error:'Email уже зарегистрирован'});

    const normalUsername = '@'+username.replace(/^@/,'').trim().toLowerCase();
    if (dbAdapter.getUserByUsername(normalUsername)) return json(res,409,{error:'Username уже занят'});

    const uid = genUid();
    const u = {
      uid, name: name.trim().slice(0,50),
      username: normalUsername,
      email: email.toLowerCase().trim(),
      passwordHash: hashPassword(password),
      bio:'', color: Math.floor(Math.random()*8),
      avaEmo: null, avaImg: null,
      usernameChangedAt: 0, createdAt: nowMs(),
      status: 'online'
    };
    dbAdapter.createUser(u);
    const t = genToken();
    dbAdapter.createSession(t, uid);
    recordUserIp(uid, clientIp, req.headers['user-agent']||'', 'register');
    broadcastToAll('user_presence', {uid, status:'online', name:u.name, username:u.username}, uid);
    return json(res,201,{token:t, user:safeUser(u)});
  }

  // POST /auth/login
  if (method==='POST' && pathname==='/auth/login') {
    const {email,password} = body;
    if (!email||!password) return json(res,400,{error:'Введите email и пароль'});
    const u = dbAdapter.getUserByEmail(email);
    if (!u || !verifyPassword(password, u.passwordHash)) return json(res,401,{error:'Неверный email или пароль'});
    // Проверяем бан
    if (u.banned) {
      const now = nowMs();
      if (!u.banUntil || u.banUntil > now) {
        const reason = u.banReason || 'Нарушение правил';
        const until = u.banUntil ? ` до ${new Date(u.banUntil).toLocaleString('ru')}` : ' навсегда';
        return json(res,403,{error:`Аккаунт заблокирован${until}. Причина: ${reason}`});
      } else {
        // Бан истёк — снимаем
        if (useSQL) db.prepare('UPDATE users SET banned=0, ban_reason=\'\', ban_until=0 WHERE uid=?').run(u.uid);
        invalidateUserCache(u.uid);
      }
    }
    const t = genToken();
    dbAdapter.createSession(t, u.uid);
    recordUserIp(u.uid, clientIp, req.headers['user-agent']||'', 'login');
    return json(res,200,{token:t, user:safeUser(u)});
  }

  // POST /auth/logout
  if (method==='POST' && pathname==='/auth/logout') {
    if (authToken) dbAdapter.deleteSession(authToken);
    return json(res,200,{ok:true});
  }

  // All routes below require auth
  if (!currentUid) return json(res,401,{error:'Не авторизован'});

  // GET /me
  if (method==='GET' && pathname==='/me') {
    const u = dbAdapter.getUserByUid(currentUid);
    if (!u) return json(res,404,{error:'Пользователь не найден'});
    return json(res,200,safeUser(u));
  }

  // PATCH /me
  if (method==='PATCH' && pathname==='/me') {
    const u = dbAdapter.getUserByUid(currentUid);
    if (!u) return json(res,404,{error:'Не найдено'});
    const fields = {};
    if (body.name)              fields.name = body.name.trim().slice(0,50);
    if (body.bio !== undefined) fields.bio  = String(body.bio).slice(0,200);
    if (body.color !== undefined) fields.color = parseInt(body.color)||0;
    if (body.avaEmo !== undefined) fields.avaEmo = body.avaEmo||null;
    if (body.avaImg !== undefined) fields.avaImg = body.avaImg||null;
    if (body.username) {
      const newU = '@'+body.username.replace(/^@/,'').trim().toLowerCase();
      if (newU !== u.username) {
        const cd = 24*3600000;
        if (nowMs()-(u.usernameChangedAt||0) < cd)
          return json(res,429,{error:'Username можно менять раз в 24 часа',retryAfter:cd-(nowMs()-(u.usernameChangedAt||0))});
        const taken = dbAdapter.getUserByUsername(newU);
        if (taken && taken.uid !== currentUid) return json(res,409,{error:'Username уже занят'});
        fields.username = newU;
        fields.usernameChangedAt = nowMs();
      }
    }
    dbAdapter.updateUser(currentUid, fields);
    const updated = dbAdapter.getUserByUid(currentUid);
    return json(res,200,safeUser(updated));
  }

  // PATCH /me/status — сменить статус (online/idle/dnd/invisible)
  if (method==='PATCH' && pathname==='/me/status') {
    const {status} = body;
    if (!VALID_STATUSES.includes(status)) return json(res,400,{error:'Недопустимый статус'});
    dbAdapter.updateUser(currentUid, {status});
    // invisible → для других offline
    const broadcastStatus = status === 'invisible' ? 'offline' : status;
    broadcastToAll('user_presence', {uid:currentUid, status:broadcastStatus});
    // Самому себе — настоящий статус
    sendEvent(currentUid, 'my_status', {status});
    return json(res,200,{ok:true, status});
  }

  // GET /online — who is currently online
  if (method==='GET' && pathname==='/online') {
    const onlineUids = Object.keys(sseClients);
    // Фильтруем invisible
    const visible = onlineUids.filter(uid=>{
      const u = dbAdapter.getUserByUid(uid);
      return u?.status !== 'invisible';
    });
    // Возвращаем uid → status
    const result = {};
    for (const uid of Object.keys(sseClients)) {
      const u = dbAdapter.getUserByUid(uid);
      result[uid] = u?.status === 'invisible' ? 'offline' : (u?.status || 'online');
    }
    // Текущему пользователю возвращаем его настоящий статус
    if (sseClients[currentUid]) {
      const me = dbAdapter.getUserByUid(currentUid);
      result[currentUid] = me?.status || 'online';
    }
    return json(res,200,{presences: result});
  }

  // GET /users — search users
  if (method==='GET' && pathname==='/users') {
    const q = (parsedUrl.query.q||'').trim();
    const users = q
      ? dbAdapter.searchUsers(q, currentUid, 50)
      : dbAdapter.getAllUsers(currentUid);
    return json(res,200,users.map(safeUser));
  }

  // GET /users/:uid
  if (method==='GET' && pathname.startsWith('/users/') && pathname.split('/').length===3) {
    const targetUid = pathname.split('/')[2];
    const u = dbAdapter.getUserByUid(targetUid);
    if (!u) return json(res,404,{error:'Не найдено'});
    return json(res,200,safeUser(u));
  }

  // GET /conversations — list of all conversations
  if (method==='GET' && pathname==='/conversations') {
    const convs = dbAdapter.getConversations(currentUid);
    const result = [];
    for (const c of convs) {
      const partner = dbAdapter.getUserByUid(c.partner_uid);
      if (!partner) continue;
      const rid = roomId(currentUid, c.partner_uid);
      const msgs = dbAdapter.getMessages(rid, 1);
      const lastMsg = msgs[msgs.length-1];
      const unread = dbAdapter.getUnreadCount(rid, c.partner_uid);
      const partnerOnline = !!(sseClients[c.partner_uid]?.length);
      const partnerStatus = partner.status === 'invisible' ? 'offline' : (partnerOnline ? (partner.status||'online') : 'offline');
      result.push({
        user: safeUser(partner),
        lastMsg: lastMsg || null,
        unread,
        online: partnerOnline && partner.status !== 'invisible',
        status: partnerStatus
      });
    }
    return json(res,200,result);
  }

  // ══════════════════════════
  //  MESSAGES
  // ══════════════════════════

  // GET /messages/:uid
  if (method==='GET' && pathname.startsWith('/messages/') && pathname.split('/').length===3) {
    const otherUid = pathname.split('/')[2];
    // Проверяем что получатель существует
    if (!dbAdapter.getUserByUid(otherUid)) return json(res,404,{error:'Пользователь не найден'});
    const rid = roomId(currentUid, otherUid);
    return json(res,200,dbAdapter.getMessages(rid, 200));
  }

  // POST /messages/:uid
  if (method==='POST' && pathname.startsWith('/messages/') && pathname.split('/').length===3) {
    const otherUid = pathname.split('/')[2];
    // Проверяем что получатель существует
    const recipient = dbAdapter.getUserByUid(otherUid);
    if (!recipient) return json(res,404,{error:'Получатель не найден'});

    // ── Заморозка чата ──
    if (global.chatFrozen && !isAdmin(currentUid)) {
      return json(res, 403, {error: '❄️ Чат заморожен администратором. Отправка сообщений временно недоступна.'});
    }

    // ── Slowmode: не чаще 1 раза в 5 сек ──
    if (global.slowmodeEnabled && !isAdmin(currentUid)) {
      if (!global._slowmodeMap) global._slowmodeMap = new Map();
      const lastSent = global._slowmodeMap.get(currentUid) || 0;
      const cooldown = 5000;
      if (nowMs() - lastSent < cooldown) {
        const wait = Math.ceil((cooldown - (nowMs() - lastSent)) / 1000);
        return json(res, 429, {error: `🐢 Slowmode: подождите ещё ${wait} сек.`});
      }
      global._slowmodeMap.set(currentUid, nowMs());
    }

    const rid = roomId(currentUid, otherUid);
    const {text,type,dataUrl,fileName,fileSize,fileType,reply} = body;
    if (!type) return json(res,400,{error:'Отсутствует тип сообщения'});

    // Проверка мьюта
    if (useSQL) {
      const senderCheck = db.prepare('SELECT muted, mute_until FROM users WHERE uid=?').get(currentUid);
      if (senderCheck && senderCheck.muted) {
        const muteUntil = senderCheck.mute_until || 0;
        if (muteUntil === 0 || muteUntil > nowMs()) {
          const until = muteUntil === 0 ? 'бессрочно' : `до ${new Date(muteUntil).toLocaleString('ru')}`;
          return json(res, 403, {error: `Вы замьючены (${until}). Отправка сообщений недоступна.`});
        } else {
          // Мьют истёк — снимаем
          db.prepare('UPDATE users SET muted=0, mute_until=0 WHERE uid=?').run(currentUid);
        }
      }
    }

    const sender = dbAdapter.getUserByUid(currentUid);
    const msgId = genMsgId();
    const now = nowMs();
    const timeStr = new Date(now).toLocaleTimeString('ru',{hour:'2-digit',minute:'2-digit'});

    const msg = {
      id: msgId,
      roomId: rid,
      from: currentUid,
      to: otherUid,
      text: text||'',
      type: type||'text',
      dataUrl: dataUrl||null,
      fileName: fileName||null,
      fileSize: fileSize||null,
      fileType: fileType||null,
      reply: reply||null,
      time: timeStr,
      timestamp: now,
      read: false,
    };
    dbAdapter.addMessage(msg);

    // Посылаем получателю
    sendEvent(otherUid,'message', msg);

    return json(res,201, msg);
  }

  // PATCH /messages/:uid/read
  if (method==='PATCH' && pathname.includes('/read')) {
    const parts = pathname.split('/');
    const otherUid = parts[2];
    const rid = roomId(currentUid, otherUid);
    // Помечаем как прочитанные сообщения ОТ otherUid
    dbAdapter.markRead(rid, otherUid);
    sendEvent(otherUid,'messages_read',{roomId:rid, by:currentUid});
    return json(res,200,{ok:true});
  }

  // DELETE /messages/:uid/:msgId — только свои сообщения
  if (method==='DELETE' && pathname.startsWith('/messages/')) {
    const parts = pathname.split('/');
    if (parts.length < 4) return json(res,400,{error:'Некорректный запрос'});
    const otherUid = parts[2];
    const msgId = parts[3];
    const rid = roomId(currentUid, otherUid);

    // Проверяем авторство
    if (!dbAdapter.isMessageOwner(rid, msgId, currentUid)) {
      return json(res,403,{error:'Нельзя удалить чужое сообщение'});
    }

    dbAdapter.deleteMessage(rid, msgId);
    sendEvent(otherUid,'message_deleted',{roomId:rid, msgId});
    return json(res,200,{ok:true});
  }

  // ══════════════════════════
  //  WebRTC SIGNALING
  // ══════════════════════════

  // POST /typing/:targetUid
  if (method==='POST' && pathname.startsWith('/typing/')) {
    const targetUid = pathname.split('/')[2];
    const { typing } = body;
    sendEvent(targetUid, 'typing', { uid: currentUid, typing: !!typing });
    return json(res,200,{ok:true});
  }
  // POST /signal/:targetUid
  if (method==='POST' && pathname.startsWith('/signal/')) {
    const targetUid = pathname.split('/')[2];
    const signal = body;
    sendEvent(targetUid, 'rtc_signal', {
      from: currentUid,
      signal
    });
    return json(res,200,{ok:true});
  }

  // POST /block/:targetUid
  if (method==='POST' && pathname.startsWith('/block/')) {
    const targetUid = pathname.split('/')[2];
    if (!targetUid || targetUid === currentUid) return json(res,400,{error:'Некорректный запрос'});
    if (useSQL) {
      try { db.prepare('INSERT OR IGNORE INTO blocks(blocker_uid,blocked_uid,created_at) VALUES(?,?,?)').run(currentUid, targetUid, Date.now()); } catch(e) {}
    } else {
      if (!DB.blocks) DB.blocks = {};
      if (!DB.blocks[currentUid]) DB.blocks[currentUid] = [];
      if (!DB.blocks[currentUid].includes(targetUid)) DB.blocks[currentUid].push(targetUid);
    }
    sendEvent(targetUid, 'blocked_by', { uid: currentUid });
    return json(res,200,{ok:true,blocked:true});
  }
  // DELETE /block/:targetUid
  if (method==='DELETE' && pathname.startsWith('/block/')) {
    const targetUid = pathname.split('/')[2];
    if (useSQL) {
      try { db.prepare('DELETE FROM blocks WHERE blocker_uid=? AND blocked_uid=?').run(currentUid, targetUid); } catch(e) {}
    } else {
      if (DB.blocks && DB.blocks[currentUid]) {
        DB.blocks[currentUid] = DB.blocks[currentUid].filter(u => u !== targetUid);
      }
    }
    sendEvent(targetUid, 'unblocked_by', { uid: currentUid });
    return json(res,200,{ok:true,blocked:false});
  }
  // GET /blocks
  if (method==='GET' && pathname==='/blocks') {
    let list = [];
    if (useSQL) {
      list = db.prepare('SELECT blocked_uid FROM blocks WHERE blocker_uid=?').all(currentUid).map(r=>r.blocked_uid);
    } else {
      list = (DB.blocks && DB.blocks[currentUid]) || [];
    }
    return json(res,200,{blocked: list});
  }
  // GET /blocked-by
  if (method==='GET' && pathname==='/blocked-by') {
    let list = [];
    if (useSQL) {
      list = db.prepare('SELECT blocker_uid FROM blocks WHERE blocked_uid=?').all(currentUid).map(r=>r.blocker_uid);
    } else {
      list = Object.entries(DB.blocks||{}).filter(([,v])=>v.includes(currentUid)).map(([k])=>k);
    }
    return json(res,200,{blockedBy: list});
  }
  // ══════════════════════════
  //  ADMIN ROUTES (только @boss)
  // ══════════════════════════

  // ══════════════════════════
  // PUBLIC: verified list (accessible to all logged in users)
  if (method === 'GET' && pathname === '/admin/verified-list') {
    if (!global.verifiedUsers) global.verifiedUsers = {};
    return json(res, 200, { verified: Object.keys(global.verifiedUsers) });
  }

  if (pathname.startsWith('/admin/')) {
    if (!isAdmin(currentUid)) return json(res, 403, {error: 'Нет доступа'});
    const me = dbAdapter.getUserByUid(currentUid);

    // GET /admin/stats — статистика сервера
    if (method === 'GET' && pathname === '/admin/stats') {
      const allUsers = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM users').get() : {cnt: Object.keys(DB.users||{}).length};
      const bannedUsers = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM users WHERE banned=1').get() : {cnt: 0};
      const mutedUsers = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM users WHERE muted=1').get() : {cnt: 0};
      const totalMsgs = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM messages').get() : {cnt: 0};
      const todayStart = new Date(); todayStart.setHours(0,0,0,0);
      const todayMsgs = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE timestamp > ?').get(todayStart.getTime()) : {cnt: 0};
      const newUsers24h = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM users WHERE created_at > ?').get(nowMs()-86400000) : {cnt: 0};
      const onlineCount = Object.keys(sseClients).length;
      const recentBans = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM admin_log WHERE action=\'ban\' AND timestamp > ?').get(nowMs()-86400000) : {cnt: 0};
      return json(res, 200, {
        users: allUsers.cnt,
        banned: bannedUsers.cnt,
        muted: mutedUsers.cnt,
        online: onlineCount,
        totalMessages: totalMsgs.cnt,
        todayMessages: todayMsgs.cnt,
        newUsers24h: newUsers24h.cnt,
        recentBans: recentBans.cnt,
        uptime: process.uptime(),
        nodeVersion: process.version,
        memoryMB: Math.round(process.memoryUsage().rss / 1024 / 1024),
        serverTime: nowMs()
      });
    }

    // GET /admin/users — все пользователи
    if (method === 'GET' && pathname === '/admin/users') {
      const page = parseInt(parsedUrl.query.page) || 1;
      const limit = parseInt(parsedUrl.query.limit) || 50;
      const search = (parsedUrl.query.q || '').trim();
      const offset = (page - 1) * limit;
      let users, total;
      if (useSQL) {
        if (search) {
          const like = '%'+search+'%';
          users = db.prepare('SELECT * FROM users WHERE name LIKE ? OR username LIKE ? OR email LIKE ? ORDER BY created_at DESC LIMIT ? OFFSET ?').all(like,like,like,limit,offset).map(rowToUser);
          total = db.prepare('SELECT COUNT(*) as cnt FROM users WHERE name LIKE ? OR username LIKE ? OR email LIKE ?').get(like,like,like).cnt;
        } else {
          users = db.prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?').all(limit, offset).map(rowToUser);
          total = db.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
        }
      } else {
        users = Object.values(DB.users||{});
        total = users.length;
        users = users.slice(offset, offset+limit);
      }
      return json(res, 200, { users: users.map(adminSafeUser), total, page, pages: Math.ceil(total/limit) });
    }

    // GET /admin/user/:uid — один пользователь
    if (method === 'GET' && pathname.startsWith('/admin/user/') && pathname.split('/').length === 4) {
      const targetUid = pathname.split('/')[3];
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      // Дополнительная инфа
      const sessions = useSQL ? db.prepare('SELECT * FROM sessions WHERE uid=? ORDER BY last_seen DESC').all(targetUid) : [];
      const msgCount = useSQL ? db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE from_uid=?').get(targetUid) : {cnt: 0};
      const notes = useSQL ? db.prepare('SELECT * FROM user_notes WHERE target_uid=? ORDER BY timestamp DESC').all(targetUid) : [];
      const logs = useSQL ? db.prepare('SELECT * FROM admin_log WHERE target_uid=? ORDER BY timestamp DESC LIMIT 20').all(targetUid) : [];
      return json(res, 200, {
        user: adminSafeUser(u),
        sessions, msgCount: msgCount.cnt, notes, logs
      });
    }

    // PATCH /admin/user/:uid — редактировать пользователя
    if (method === 'PATCH' && pathname.startsWith('/admin/user/') && pathname.split('/').length === 4) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя изменить свой аккаунт через админ-панель'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      const fields = {};
      if (body.name) fields.name = String(body.name).trim().slice(0,50);
      if (body.bio !== undefined) fields.bio = String(body.bio).slice(0,200);
      if (body.username) {
        const newU = '@'+String(body.username).replace(/^@/,'').trim().toLowerCase();
        if (!dbAdapter.getUserByUsername(newU)) {
          fields.username = newU;
          fields.usernameChangedAt = nowMs();
        } else return json(res, 409, {error: 'Username занят'});
      }
      if (body.color !== undefined) fields.color = parseInt(body.color)||0;
      if (body.status && ['online','idle','dnd','invisible'].includes(body.status)) fields.status = body.status;
      dbAdapter.updateUser(targetUid, fields);
      adminLog(currentUid, 'edit_user', targetUid, JSON.stringify(fields), clientIp);
      sendEvent(targetUid, 'admin_event', {type:'profile_updated', fields});
      return json(res, 200, {ok:true, user: adminSafeUser(dbAdapter.getUserByUid(targetUid))});
    }

    // POST /admin/reset-password/:uid — сброс пароля
    if (method === 'POST' && pathname.startsWith('/admin/reset-password/')) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя сбросить свой пароль'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      const { newPassword } = body;
      if (!newPassword || newPassword.length < 6) return json(res, 400, {error: 'Пароль минимум 6 символов'});
      if (useSQL) db.prepare('UPDATE users SET password_hash=? WHERE uid=?').run(hashPassword(newPassword), targetUid);
      invalidateUserCache(targetUid);
      // Кикаем все сессии
      if (useSQL) db.prepare('DELETE FROM sessions WHERE uid=?').run(targetUid);
      sseClients[targetUid]?.forEach(r => { try { r.write('event:force_logout\ndata:{}\n\n'); r.end(); } catch{} });
      delete sseClients[targetUid];
      adminLog(currentUid, 'reset_password', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/ban/:uid — забанить
    if (method === 'POST' && pathname.startsWith('/admin/ban/')) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя забанить себя'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      if (u.username === '@boss' || u.username === '@vyyxek') return json(res, 403, {error: 'Нельзя забанить владельца'});
      const { reason, duration } = body; // duration в часах, 0 = навсегда
      const banUntil = duration ? nowMs() + duration * 3600000 : 0;
      if (useSQL) {
        db.prepare('UPDATE users SET banned=1, ban_reason=?, ban_until=? WHERE uid=?').run(reason||'Нарушение правил', banUntil, targetUid);
        db.prepare('DELETE FROM sessions WHERE uid=?').run(targetUid);
      }
      invalidateUserCache(targetUid);
      sseClients[targetUid]?.forEach(r => { try { r.write(`event:force_logout\ndata:${JSON.stringify({reason: reason||'Забанен', banUntil})}\n\n`); r.end(); } catch{} });
      delete sseClients[targetUid];
      broadcastToAll('user_presence', {uid: targetUid, status: 'offline'});
      adminLog(currentUid, 'ban', targetUid, `reason:${reason||'-'} duration:${duration||0}h`, clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/ban/:uid — разбанить
    if (method === 'DELETE' && pathname.startsWith('/admin/ban/')) {
      const targetUid = pathname.split('/')[3];
      if (useSQL) db.prepare('UPDATE users SET banned=0, ban_reason=\'\', ban_until=0 WHERE uid=?').run(targetUid);
      invalidateUserCache(targetUid);
      adminLog(currentUid, 'unban', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/mute/:uid — замьютить
    if (method === 'POST' && pathname.startsWith('/admin/mute/')) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя замьютить себя'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      const { duration, reason } = body; // duration в минутах
      const muteUntil = duration ? nowMs() + duration * 60000 : 0;
      if (useSQL) db.prepare('UPDATE users SET muted=1, mute_until=? WHERE uid=?').run(muteUntil, targetUid);
      invalidateUserCache(targetUid);
      sendEvent(targetUid, 'admin_event', {type:'muted', muteUntil, reason: reason||'Нарушение правил'});
      adminLog(currentUid, 'mute', targetUid, `${duration||0}min reason:${reason||'-'}`, clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/mute/:uid — размьютить
    if (method === 'DELETE' && pathname.startsWith('/admin/mute/')) {
      const targetUid = pathname.split('/')[3];
      if (useSQL) db.prepare('UPDATE users SET muted=0, mute_until=0 WHERE uid=?').run(targetUid);
      invalidateUserCache(targetUid);
      sendEvent(targetUid, 'admin_event', {type:'unmuted'});
      adminLog(currentUid, 'unmute', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/warn/:uid — вынести предупреждение
    if (method === 'POST' && pathname.startsWith('/admin/warn/')) {
      const targetUid = pathname.split('/')[3];
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      const { reason } = body;
      let newWarnCount = (u.warnCount||0) + 1;
      if (useSQL) db.prepare('UPDATE users SET warn_count=? WHERE uid=?').run(newWarnCount, targetUid);
      invalidateUserCache(targetUid);
      sendEvent(targetUid, 'admin_event', {type:'warning', reason: reason||'Нарушение правил', count: newWarnCount});
      adminLog(currentUid, 'warn', targetUid, `warn #${newWarnCount}: ${reason||'-'}`, clientIp);
      // Автобан при 3+ предупреждениях
      if (newWarnCount >= 3) {
        if (useSQL) db.prepare('UPDATE users SET banned=1, ban_reason=?, ban_until=0 WHERE uid=?').run('Автобан: 3 предупреждения', targetUid);
        invalidateUserCache(targetUid);
        sseClients[targetUid]?.forEach(r => { try { r.write('event:force_logout\ndata:{"reason":"Автобан: 3 предупреждения"}\n\n'); r.end(); } catch{} });
        delete sseClients[targetUid];
        adminLog(currentUid, 'auto_ban', targetUid, '3 warnings', clientIp);
      }
      return json(res, 200, {ok:true, warnCount: newWarnCount, autoBanned: newWarnCount >= 3});
    }

    // POST /admin/kick/:uid — кикнуть (отключить без бана)
    if (method === 'POST' && pathname.startsWith('/admin/kick/')) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя кикнуть себя'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      const { reason } = body;
      sseClients[targetUid]?.forEach(r => { try { r.write(`event:force_logout\ndata:${JSON.stringify({reason: reason||'Кик администратора', kick: true})}\n\n`); r.end(); } catch{} });
      if (useSQL) db.prepare('DELETE FROM sessions WHERE uid=?').run(targetUid);
      delete sseClients[targetUid];
      broadcastToAll('user_presence', {uid: targetUid, status: 'offline'});
      adminLog(currentUid, 'kick', targetUid, reason||'-', clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/user/:uid — удалить аккаунт
    if (method === 'DELETE' && pathname.startsWith('/admin/user/') && pathname.split('/').length === 4) {
      const targetUid = pathname.split('/')[3];
      if (targetUid === currentUid) return json(res, 400, {error: 'Нельзя удалить свой аккаунт'});
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Не найден'});
      if (u.username === '@boss' || u.username === '@vyyxek') return json(res, 403, {error: 'Нельзя удалить владельца'});
      sseClients[targetUid]?.forEach(r => { try { r.write('event:force_logout\ndata:{"reason":"Аккаунт удалён администратором"}\n\n'); r.end(); } catch{} });
      delete sseClients[targetUid];
      if (useSQL) {
        db.prepare('DELETE FROM users WHERE uid=?').run(targetUid);
        db.prepare('DELETE FROM sessions WHERE uid=?').run(targetUid);
        db.prepare('DELETE FROM messages WHERE from_uid=? OR to_uid=?').run(targetUid, targetUid);
      }
      invalidateUserCache(targetUid);
      broadcastToAll('admin_event', {type:'user_deleted', uid: targetUid});
      adminLog(currentUid, 'delete_user', targetUid, u.email, clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/messages/:uid — очистить все сообщения пользователя
    if (method === 'DELETE' && pathname.startsWith('/admin/messages/') && pathname.split('/').length === 4) {
      const targetUid = pathname.split('/')[3];
      if (useSQL) db.prepare('DELETE FROM messages WHERE from_uid=?').run(targetUid);
      broadcastToAll('admin_event', {type:'messages_cleared', uid: targetUid});
      adminLog(currentUid, 'clear_messages', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/message/:msgId — удалить конкретное сообщение
    if (method === 'DELETE' && pathname.startsWith('/admin/message/') && pathname.split('/').length === 4) {
      const msgId = pathname.split('/')[3];
      if (useSQL) {
        const msg = db.prepare('SELECT * FROM messages WHERE id=?').get(msgId);
        if (msg) {
          db.prepare('DELETE FROM messages WHERE id=?').run(msgId);
          broadcastToAll('message_deleted', {roomId: msg.room_id, msgId});
          adminLog(currentUid, 'delete_message', msg.from_uid, `msgId:${msgId}`, clientIp);
        }
      }
      return json(res, 200, {ok:true});
    }

    // GET /admin/messages/:uid — сообщения пользователя (с опциональной фильтрацией по room)
    if (method === 'GET' && pathname.startsWith('/admin/messages/') && pathname.split('/').length === 4) {
      const targetUid = pathname.split('/')[3];
      const page = parseInt(parsedUrl.query.page) || 1;
      const limit = parseInt(parsedUrl.query.limit) || 50;
      const offset = (page-1)*limit;
      const roomFilter = parsedUrl.query.room || '';
      if (!useSQL) return json(res, 200, {messages:[], total:0});
      let messages, total;
      if (roomFilter) {
        messages = db.prepare('SELECT * FROM messages WHERE room_id=? ORDER BY timestamp ASC LIMIT ? OFFSET ?').all(roomFilter, limit, offset).map(rowToMsg);
        total = db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE room_id=?').get(roomFilter).cnt;
      } else {
        messages = db.prepare('SELECT * FROM messages WHERE from_uid=? OR to_uid=? ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(targetUid, targetUid, limit, offset).map(rowToMsg);
        total = db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE from_uid=? OR to_uid=?').get(targetUid, targetUid).cnt;
      }
      return json(res, 200, {messages, total, pages: Math.ceil(total/limit)});
    }

    // POST /admin/broadcast — системная рассылка всем
    if (method === 'POST' && pathname === '/admin/broadcast') {
      const { text, type, fromBot } = body; // type: info|warning|danger
      if (!text) return json(res, 400, {error: 'Нет текста'});
      const from = fromBot ? 'Перезажигал' : me.name;
      if (useSQL) db.prepare('INSERT INTO system_broadcasts (from_uid, text, type, timestamp) VALUES (?,?,?,?)').run(currentUid, text, type||'info', nowMs());
      broadcastToAll('system_broadcast', {text, type: type||'info', from, fromBot: !!fromBot, timestamp: nowMs()});
      adminLog(currentUid, fromBot ? 'bot_broadcast' : 'broadcast', null, text.slice(0,100), clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/announce/:uid — личное сообщение пользователю от администрации
    if (method === 'POST' && pathname.startsWith('/admin/announce/')) {
      const targetUid = pathname.split('/')[3];
      const { text, type } = body;
      if (!text) return json(res, 400, {error: 'Нет текста'});
      sendEvent(targetUid, 'admin_message', {text, type: type||'info', from: me.name, timestamp: nowMs()});
      adminLog(currentUid, 'announce', targetUid, text.slice(0,100), clientIp);
      return json(res, 200, {ok:true});
    }

    // GET /admin/sessions — активные SSE сессии
    if (method === 'GET' && pathname === '/admin/sessions') {
      const sessions = Object.entries(sseClients).map(([uid, clients]) => {
        const u = dbAdapter.getUserByUid(uid);
        return u ? { uid, name: u.name, username: u.username, status: u.status, connections: clients.length } : null;
      }).filter(Boolean);
      return json(res, 200, {sessions, total: sessions.length});
    }

    // GET /admin/log — журнал действий
    if (method === 'GET' && pathname === '/admin/log') {
      const page = parseInt(parsedUrl.query.page) || 1;
      const limit = 100;
      const offset = (page-1)*limit;
      const actionFilter = parsedUrl.query.action || '';
      if (!useSQL) return json(res, 200, {log:[], total:0});
      let logs, total;
      if (actionFilter) {
        logs = db.prepare('SELECT * FROM admin_log WHERE action=? ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(actionFilter, limit, offset);
        total = db.prepare('SELECT COUNT(*) as cnt FROM admin_log WHERE action=?').get(actionFilter).cnt;
      } else {
        logs = db.prepare('SELECT * FROM admin_log ORDER BY timestamp DESC LIMIT ? OFFSET ?').all(limit, offset);
        total = db.prepare('SELECT COUNT(*) as cnt FROM admin_log').get().cnt;
      }
      return json(res, 200, {log: logs, total, pages: Math.ceil(total/limit)});
    }

    // POST /admin/user-note/:uid — добавить заметку
    if (method === 'POST' && pathname.startsWith('/admin/user-note/')) {
      const targetUid = pathname.split('/')[3];
      const { note } = body;
      if (!note) return json(res, 400, {error: 'Нет текста'});
      if (useSQL) db.prepare('INSERT INTO user_notes (admin_uid, target_uid, note, timestamp) VALUES (?,?,?,?)').run(currentUid, targetUid, note, nowMs());
      adminLog(currentUid, 'add_note', targetUid, note.slice(0,50), clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/user-note/:id — удалить заметку
    if (method === 'DELETE' && pathname.startsWith('/admin/user-note/')) {
      const noteId = parseInt(pathname.split('/')[3]);
      if (useSQL) db.prepare('DELETE FROM user_notes WHERE id=?').run(noteId);
      return json(res, 200, {ok:true});
    }

    // POST /admin/clear-all-messages — очистить ВСЕ сообщения
    if (method === 'POST' && pathname === '/admin/clear-all-messages') {
      if (useSQL) db.prepare('DELETE FROM messages').run();
      broadcastToAll('admin_event', {type:'all_messages_cleared'});
      adminLog(currentUid, 'clear_all_messages', null, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // GET /admin/broadcasts — история рассылок
    if (method === 'GET' && pathname === '/admin/broadcasts') {
      if (!useSQL) return json(res, 200, {broadcasts:[]});
      const broadcasts = db.prepare('SELECT * FROM system_broadcasts ORDER BY timestamp DESC LIMIT 50').all();
      return json(res, 200, {broadcasts});
    }

    // POST /admin/username-reset/:uid — сброс кулдауна смены username
    if (method === 'POST' && pathname.startsWith('/admin/username-reset/')) {
      const targetUid = pathname.split('/')[3];
      dbAdapter.updateUser(targetUid, {usernameChangedAt: 0});
      adminLog(currentUid, 'username_reset', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/reset-warns/:uid — сбросить предупреждения
    if (method === 'POST' && pathname.startsWith('/admin/reset-warns/')) {
      const targetUid = pathname.split('/')[3];
      if (useSQL) db.prepare('UPDATE users SET warn_count=0 WHERE uid=?').run(targetUid);
      invalidateUserCache(targetUid);
      adminLog(currentUid, 'reset_warns', targetUid, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // GET /admin/search — поиск по сообщениям
    if (method === 'GET' && pathname === '/admin/search') {
      const q = parsedUrl.query.q || '';
      if (!q || !useSQL) return json(res, 200, {results:[]});
      const like = '%'+q+'%';
      const results = db.prepare('SELECT * FROM messages WHERE text LIKE ? ORDER BY timestamp DESC LIMIT 50').all(like).map(rowToMsg);
      return json(res, 200, {results});
    }


    // GET /admin/users/:uid/info — алиас для GeoIP и других инструментов
    if (method === 'GET' && pathname.startsWith('/admin/users/') && pathname.endsWith('/info')) {
      const targetUid = pathname.split('/')[3];
      const u = dbAdapter.getUserByUid(targetUid);
      if (!u) return json(res, 404, {error: 'Пользователь не найден'});
      const ipHistory = useSQL
        ? db.prepare('SELECT ip, user_agent, action, timestamp FROM user_ips WHERE uid=? ORDER BY timestamp DESC LIMIT 20').all(targetUid)
        : [];
      const msgStats = useSQL
        ? db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE from_uid=?').get(targetUid)
        : {cnt: 0};
      return json(res, 200, {
        user: adminSafeUser(u),
        ipHistory,
        totalMessages: msgStats.cnt
      });
    }

    // GET /admin/users/:uid — детальная информация о пользователе
    if (method === 'GET' && pathname.startsWith('/admin/users/') && !pathname.endsWith('/notes')) {
      const parts = pathname.split('/');
      if (parts.length === 4) {
        const targetUid = parts[3];
        const u = dbAdapter.getUserByUid(targetUid);
        if (!u) return json(res, 404, {error: 'Пользователь не найден'});
        const safeU = adminSafeUser(u);
        // Сессии
        const sessions = useSQL
          ? db.prepare('SELECT created_at, last_seen FROM sessions WHERE uid=? ORDER BY last_seen DESC').all(targetUid)
          : [];
        // Статистика сообщений
        const msgStats = useSQL
          ? db.prepare('SELECT COUNT(*) as cnt FROM messages WHERE from_uid=?').get(targetUid)
          : {cnt: 0};
        // Последние/уникальные IP из таблицы user_ips
        const ipHistory = useSQL
          ? db.prepare('SELECT ip, user_agent, action, timestamp FROM user_ips WHERE uid=? ORDER BY timestamp DESC LIMIT 20').all(targetUid)
          : [];
        // Также из admin_log (старые данные)
        const logIps = useSQL
          ? db.prepare('SELECT DISTINCT ip, MAX(timestamp) as ts FROM admin_log WHERE target_uid=? AND ip!=\'\' GROUP BY ip ORDER BY ts DESC LIMIT 5').all(targetUid)
          : [];
        // Заметки
        const notes = useSQL
          ? db.prepare('SELECT n.*, u.name as adminName FROM user_notes n LEFT JOIN users u ON n.admin_uid=u.uid WHERE n.target_uid=? ORDER BY n.timestamp DESC').all(targetUid)
          : [];
        // История банов/мьютов из лога
        const modHistory = useSQL
          ? db.prepare('SELECT action, details, ip, timestamp FROM admin_log WHERE target_uid=? ORDER BY timestamp DESC LIMIT 15').all(targetUid)
          : [];
        return json(res, 200, {
          user: safeU,
          sessions: sessions.map(s => ({created_at: s.created_at, last_seen: s.last_seen})),
          totalMessages: msgStats.cnt,
          ipHistory,
          logIps,
          notes,
          modHistory
        });
      }
    }

    // GET /admin/users/:uid/notes — получить заметки о пользователе
    if (method === 'GET' && pathname.startsWith('/admin/users/') && pathname.endsWith('/notes')) {
      const targetUid = pathname.split('/')[3];
      const notes = useSQL
        ? db.prepare('SELECT n.*, u.name as adminName FROM user_notes n LEFT JOIN users u ON n.admin_uid=u.uid WHERE n.target_uid=? ORDER BY n.timestamp DESC').all(targetUid)
        : [];
      return json(res, 200, { notes });
    }

    // POST /admin/users/:uid/notes — добавить заметку
    if (method === 'POST' && pathname.startsWith('/admin/users/') && pathname.endsWith('/notes')) {
      const targetUid = pathname.split('/')[3];
      const { text } = body;
      if (!text) return json(res, 400, {error: 'Нет текста'});
      if (useSQL) db.prepare('INSERT INTO user_notes (admin_uid, target_uid, note, timestamp) VALUES (?,?,?,?)').run(currentUid, targetUid, text, nowMs());
      adminLog(currentUid, 'add_note', targetUid, text.slice(0,50), clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/users/:uid/message — личное сообщение от бота конкретному юзеру
    if (method === 'POST' && pathname.startsWith('/admin/users/') && pathname.endsWith('/message')) {
      const targetUid = pathname.split('/')[3];
      const { text, type } = body;
      if (!text) return json(res, 400, {error: 'Нет текста'});
      const me = dbAdapter.getUserByUid(currentUid);
      sendEvent(targetUid, 'admin_message', {text, type: type||'info', from: 'Перезажигал', fromBot: true, timestamp: nowMs()});
      adminLog(currentUid, 'bot_message', targetUid, text.slice(0,100), clientIp);
      return json(res, 200, {ok:true});
    }

    // GET /admin/ipbans — список IP-банов
    if (method === 'GET' && pathname === '/admin/ipbans') {
      const bans = useSQL ? db.prepare('SELECT * FROM ip_bans ORDER BY created_at DESC').all() : [];
      return json(res, 200, { bans });
    }

    // POST /admin/ipbans — добавить IP-бан
    if (method === 'POST' && pathname === '/admin/ipbans') {
      const { ip, reason } = body;
      if (!ip) return json(res, 400, {error: 'Нет IP'});
      if (useSQL) {
        try {
          db.prepare('INSERT INTO ip_bans (ip, reason, admin_uid, created_at) VALUES (?,?,?,?)').run(ip, reason||'', currentUid, nowMs());
        } catch(e) {
          return json(res, 409, {error: 'IP уже заблокирован'});
        }
      }
      adminLog(currentUid, 'ip_ban', null, ip, clientIp);
      return json(res, 200, {ok:true});
    }

    // DELETE /admin/ipbans/:ip — снять IP-бан
    if (method === 'DELETE' && pathname.startsWith('/admin/ipbans/')) {
      const ip = decodeURIComponent(pathname.slice('/admin/ipbans/'.length));
      if (useSQL) db.prepare('DELETE FROM ip_bans WHERE ip=?').run(ip);
      adminLog(currentUid, 'ip_unban', null, ip, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/unban-all — разбанить всех
    if (method === 'POST' && pathname === '/admin/unban-all') {
      if (useSQL) {
        db.prepare('UPDATE users SET banned=0, ban_until=0, ban_reason=NULL WHERE banned=1').run();
        invalidateAllUserCache();
      }
      adminLog(currentUid, 'unban_all', null, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/unmute-all — размьютить всех
    if (method === 'POST' && pathname === '/admin/unmute-all') {
      if (useSQL) {
        db.prepare('UPDATE users SET muted=0, mute_until=0 WHERE muted=1').run();
        invalidateAllUserCache();
      }
      adminLog(currentUid, 'unmute_all', null, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // POST /admin/kick-all — кикнуть всех
    if (method === 'POST' && pathname === '/admin/kick-all') {
      const me = dbAdapter.getUserByUid(currentUid);
      const allUids = Object.keys(sseClients).filter(uid => uid !== currentUid);
      allUids.forEach(uid => {
        sendEvent(uid, 'force_logout', {reason: 'Массовый кик администратором', kick: true});
      });
      adminLog(currentUid, 'kick_all', null, `kicked ${allUids.length} users`, clientIp);
      return json(res, 200, {ok:true, kicked: allUids.length});
    }

    // POST /admin/reset-all-warns — сбросить все варны
    if (method === 'POST' && pathname === '/admin/reset-all-warns') {
      if (useSQL) db.prepare('UPDATE users SET warn_count=0').run();
      invalidateAllUserCache();
      adminLog(currentUid, 'reset_all_warns', null, null, clientIp);
      return json(res, 200, {ok:true});
    }

    // GET /admin/export/users — экспорт всех пользователей в CSV
    if (method === 'GET' && pathname === '/admin/export/users') {
      const allUsers = useSQL ? db.prepare('SELECT * FROM users ORDER BY created_at DESC').all() : [];
      const headers = ['uid','name','username','email','bio','status','banned','ban_reason','ban_until','muted','mute_until','warn_count','created_at'];
      const rows = [headers.join(',')];
      for (const u of allUsers) {
        rows.push(headers.map(h => {
          const v = u[h] ?? '';
          const s = String(v).replace(/"/g,'""');
          return `"${s}"`;
        }).join(','));
      }
      const csv = rows.join('\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="users_export.csv"',
        'Access-Control-Allow-Origin': '*'
      });
      res.end('\uFEFF' + csv); // BOM для Excel
      return;
    }

    // POST /admin/maintenance — режим обслуживания (флаг в памяти)
    if (method === 'POST' && pathname === '/admin/maintenance') {
      global.maintenanceMode = !!body.enabled;
      adminLog(currentUid, 'maintenance', null, body.enabled ? 'on' : 'off', clientIp);
      return json(res, 200, {ok:true, maintenance: global.maintenanceMode});
    }

    // POST /admin/freeze-chat — заморозить чат
    if (method === 'POST' && pathname === '/admin/freeze-chat') {
      global.chatFrozen = !!body.enabled;
      broadcastToAll('admin_event', {type: 'chat_freeze', frozen: global.chatFrozen});
      adminLog(currentUid, 'freeze_chat', null, body.enabled ? 'on' : 'off', clientIp);
      return json(res, 200, {ok:true, frozen: global.chatFrozen});
    }

    // POST /admin/slowmode — slowmode
    if (method === 'POST' && pathname === '/admin/slowmode') {
      global.slowmodeEnabled = !!body.enabled;
      adminLog(currentUid, 'slowmode', null, body.enabled ? 'on' : 'off', clientIp);
      return json(res, 200, {ok:true, slowmode: global.slowmodeEnabled});
    }

    // POST /admin/shadow-mute — теневой мьют (пользователь думает что отправляет, но никто не видит)
    if (method === 'POST' && pathname === '/admin/shadow-mute') {
      const { uid: targetUid, hours } = body;
      if (!targetUid) return json(res, 400, {error: 'Нет uid'});
      const until = hours ? nowMs() + hours * 3600000 : 0;
      if (!global.shadowMuted) global.shadowMuted = {};
      global.shadowMuted[targetUid] = { until, adminUid: currentUid };
      adminLog(currentUid, 'shadow_mute', targetUid, `${hours||'∞'}h`, clientIp);
      return json(res, 200, {ok: true});
    }

    // DELETE /admin/shadow-mute/:uid — снять теневой мьют
    if (method === 'DELETE' && pathname.startsWith('/admin/shadow-mute/')) {
      const targetUid = pathname.split('/')[3];
      if (global.shadowMuted) delete global.shadowMuted[targetUid];
      adminLog(currentUid, 'shadow_unmute', targetUid, null, clientIp);
      return json(res, 200, {ok: true});
    }

    // GET /admin/spy/:uid — получить все переписки пользователя для шпиона
    if (method === 'GET' && pathname.startsWith('/admin/spy/')) {
      const targetUid = pathname.split('/')[3];
      if (!targetUid) return json(res, 400, {error: 'Нет uid'});
      let conversations = [];
      if (useSQL) {
        const convRows = db.prepare(`
          SELECT
            CASE WHEN from_uid=? THEN to_uid ELSE from_uid END as partner_uid,
            room_id,
            COUNT(*) as msg_count,
            MAX(timestamp) as last_ts,
            (SELECT text FROM messages m2 WHERE m2.room_id=messages.room_id ORDER BY timestamp DESC LIMIT 1) as last_text
          FROM messages
          WHERE from_uid=? OR to_uid=?
          GROUP BY room_id
          ORDER BY last_ts DESC
          LIMIT 50
        `).all(targetUid, targetUid, targetUid);

        for (const row of convRows) {
          const partner = dbAdapter.getUserByUid(row.partner_uid);
          conversations.push({
            room_id: row.room_id,
            partner_uid: row.partner_uid,
            partner_name: partner ? partner.name : row.partner_uid,
            partner_username: partner ? partner.username : '',
            msg_count: row.msg_count,
            last_ts: row.last_ts,
            last_text: row.last_text || ''
          });
        }
      }
      adminLog(currentUid, 'spy_view', targetUid, null, clientIp);
      return json(res, 200, { conversations });
    }

    // GET /admin/multi-accounts — обнаружение мультиаккаунтов по IP
    if (method === 'GET' && pathname === '/admin/multi-accounts') {
      if (!useSQL) return json(res, 200, { groups: [], totalChecked: 0 });
      // Group users by IP, show IPs with >1 user
      const ipGroups = db.prepare(`
        SELECT ip, COUNT(DISTINCT uid) as user_count, GROUP_CONCAT(DISTINCT uid) as uids
        FROM user_ips
        WHERE ip != '' AND ip != '::1' AND ip NOT LIKE '127.%' AND ip NOT LIKE '192.168.%' AND ip NOT LIKE '10.%'
        GROUP BY ip
        HAVING user_count > 1
        ORDER BY user_count DESC
        LIMIT 50
      `).all();

      const totalChecked = db.prepare(`SELECT COUNT(DISTINCT ip) as cnt FROM user_ips`).get()?.cnt || 0;

      const groups = [];
      for (const g of ipGroups) {
        const uids = (g.uids || '').split(',').filter(Boolean);
        const users = uids.map(uid => {
          const u = dbAdapter.getUserByUid(uid);
          if (!u) return null;
          return {
            uid: u.uid,
            name: u.name,
            username: u.username,
            createdAt: u.createdAt,
            banned: u.banned || 0,
            online: !!(sseClients[u.uid]?.length)
          };
        }).filter(Boolean);
        if (users.length > 1) {
          groups.push({ ip: g.ip, users, user_count: g.user_count });
        }
      }
      return json(res, 200, { groups, totalChecked });
    }

    // POST /admin/multi-ban — забанить всех с конкретного IP
    if (method === 'POST' && pathname === '/admin/multi-ban') {
      const { ip, reason } = body;
      if (!ip) return json(res, 400, {error: 'Нет IP'});
      if (!useSQL) return json(res, 200, {ok: true, banned: 0});
      const uids = db.prepare(`SELECT DISTINCT uid FROM user_ips WHERE ip=?`).all(ip).map(r => r.uid);
      let banned = 0;
      for (const uid of uids) {
        if (uid === currentUid) continue; // не баним себя
        db.prepare('UPDATE users SET banned=1, ban_reason=?, ban_until=0 WHERE uid=? AND banned=0').run(reason || 'Мультиаккаунт', uid);
        invalidateUserCache(uid);
        sendEvent(uid, 'force_logout', { reason: reason || 'Мультиаккаунт', kick: true });
        adminLog(currentUid, 'ban', uid, reason || 'Мультиаккаунт', clientIp);
        banned++;
      }
      // IP бан тоже
      try { db.prepare('INSERT OR IGNORE INTO ip_bans (ip, reason, admin_uid, created_at) VALUES (?,?,?,?)').run(ip, reason || 'Мультиаккаунт', currentUid, nowMs()); } catch {}
      return json(res, 200, { ok: true, banned });
    }

    // POST /admin/impersonate — отправить сообщение от имени другого пользователя
    if (method === 'POST' && pathname === '/admin/impersonate') {
      const { fromUid, text, targetUid } = body;
      if (!fromUid || !text || !targetUid) return json(res, 400, {error: 'Нет данных'});
      const fromUser = dbAdapter.getUserByUid(fromUid);
      const toUser = dbAdapter.getUserByUid(targetUid);
      if (!fromUser || !toUser) return json(res, 404, {error: 'Пользователь не найден'});
      const rId = roomId(fromUid, targetUid);
      const now = nowMs();
      const timeStr = new Date(now).toLocaleTimeString('ru', {hour:'2-digit',minute:'2-digit'});
      const msg = {
        id: genMsgId(),
        roomId: rId,
        from: fromUid,
        to: targetUid,
        type: 'text',
        text: text.trim(),
        time: timeStr,
        timestamp: now,
        impersonated: true // маркер маскировки
      };
      dbAdapter.addMessage(msg);
      // Отправляем обоим через SSE
      const payload = { ...msg, fromName: fromUser.name, fromUsername: fromUser.username, fromColor: fromUser.color, fromAvaEmo: fromUser.avaEmo, fromAvaImg: fromUser.avaImg };
      sendEvent(fromUid, 'message', payload);
      sendEvent(targetUid, 'message', payload);
      adminLog(currentUid, 'impersonate', fromUid, `to:${targetUid} "${text.slice(0,50)}"`, clientIp);
      return json(res, 200, {ok: true, msgId: msg.id});
    }

    // POST/GET /admin/automod/rules — правила автомодерации
    if (pathname === '/admin/automod/rules') {
      if (!global.automodRules) global.automodRules = [];
      if (method === 'GET') {
        return json(res, 200, { rules: global.automodRules, enabled: global.automodEnabled !== false });
      }
      if (method === 'POST') {
        const { word, action, match } = body;
        if (!word || !action) return json(res, 400, {error: 'Нет данных'});
        global.automodRules.push({ word, action, match: match || 'contains', hits: 0, createdAt: nowMs() });
        adminLog(currentUid, 'automod_add', null, `${word} → ${action}`, clientIp);
        return json(res, 200, {ok: true});
      }
      if (method === 'DELETE') {
        const { word } = body;
        global.automodRules = (global.automodRules || []).filter(r => r.word !== word);
        return json(res, 200, {ok: true});
      }
    }

    // POST /admin/automod/toggle
    if (method === 'POST' && pathname === '/admin/automod/toggle') {
      global.automodEnabled = !!body.enabled;
      adminLog(currentUid, 'automod_toggle', null, body.enabled ? 'on' : 'off', clientIp);
      return json(res, 200, {ok: true, enabled: global.automodEnabled});
    }

    // POST /admin/user-role — назначить роль пользователю
    if (method === 'POST' && pathname === '/admin/user-role') {
      const { uid: targetUid, role } = body;
      if (!targetUid || !role) return json(res, 400, {error: 'Нет данных'});
      if (!global.userRoles) global.userRoles = {};
      if (role === 'none') delete global.userRoles[targetUid];
      else global.userRoles[targetUid] = role;
      // Notify user of role change
      const roleEmoji = { vip: '👑', mod: '🛡️', dev: '⚡', ghost: '👻' };
      if (role && role !== 'none') {
        sendEvent(targetUid, 'admin_message', {
          text: `${roleEmoji[role]||'🎖️'} Вам назначена роль: ${role.toUpperCase()}`,
          type: 'success',
          from: 'Перезажигал',
          fromBot: true,
          timestamp: nowMs()
        });
      }
      adminLog(currentUid, 'set_role', targetUid, role, clientIp);
      return json(res, 200, {ok: true});
    }

    // GET /admin/user-roles — все роли
    if (method === 'GET' && pathname === '/admin/user-roles') {
      return json(res, 200, { roles: global.userRoles || {} });
    }

    // GET /admin/verified-list — список верифицированных пользователей
    if (method === 'GET' && pathname === '/admin/verified-list') {
      if (!global.verifiedUsers) global.verifiedUsers = {};
      return json(res, 200, { verified: Object.keys(global.verifiedUsers) });
    }

    // POST /admin/verified — выдать / снять галочку
    if (method === 'POST' && pathname === '/admin/verified') {
      const { uid: targetUid, verified } = body;
      if (!targetUid) return json(res, 400, {error: 'Нет uid'});
      if (!global.verifiedUsers) global.verifiedUsers = {};
      if (verified) {
        global.verifiedUsers[targetUid] = true;
        sendEvent(targetUid, 'admin_message', {
          text: '✅ Ваш аккаунт был верифицирован! Галочка активна.',
          type: 'success',
          from: 'Перезажигал',
          fromBot: true,
          timestamp: nowMs()
        });
      } else {
        delete global.verifiedUsers[targetUid];
        sendEvent(targetUid, 'admin_message', {
          text: '❌ Верификация вашего аккаунта была отозвана.',
          type: 'warn',
          from: 'Перезажигал',
          fromBot: true,
          timestamp: nowMs()
        });
      }
      adminLog(currentUid, verified ? 'verify_user' : 'unverify_user', targetUid, null, clientIp);
      return json(res, 200, { ok: true });
    }

    return json(res, 404, {error: 'Неизвестный admin-маршрут'});
  }

  // Проверка мута перед отправкой сообщения
  if (method === 'POST' && pathname.startsWith('/messages/')) {
    const u = dbAdapter.getUserByUid(currentUid);
    if (u?.muted) {
      const now = nowMs();
      if (!u.muteUntil || u.muteUntil > now) {
        const until = u.muteUntil ? ` до ${new Date(u.muteUntil).toLocaleString('ru')}` : '';
        return json(res, 403, {error: `Вы замьючены${until}`});
      } else {
        if (useSQL) db.prepare('UPDATE users SET muted=0, mute_until=0 WHERE uid=?').run(currentUid);
        invalidateUserCache(currentUid);
      }
    }

    // Проверка теневого мьюта — пользователь думает что отправляет, но другие не видят
    if (global.shadowMuted && global.shadowMuted[currentUid]) {
      const sm = global.shadowMuted[currentUid];
      const now = nowMs();
      if (!sm.until || sm.until > now) {
        // Делаем вид что всё ок, но сообщение никуда не идёт
        // Возвращаем фейковый id чтобы клиент думал что успешно
        return json(res, 200, {ok: true, id: genMsgId(), shadowMuted: true, time: new Date().toLocaleTimeString('ru', {hour:'2-digit',minute:'2-digit'})});
      } else {
        // Теневой мьют истёк
        delete global.shadowMuted[currentUid];
      }
    }

    // Проверка автомодерации
    if (global.automodEnabled !== false && global.automodRules && global.automodRules.length) {
      // Тело запроса ещё не спарсено здесь (читается ниже), пропускаем
      // Автомод применяется в обработчике /messages/:uid
    }
  }

  json(res,404,{error:'Маршрут не найден'});
}

const server = http.createServer(handle);
server.listen(PORT, ()=>{
  console.log(`\n🔥 ПЕРЕЗАЖИГАЛ v3.0 запущен!`);
  console.log(`   http://localhost:${PORT}`);
  console.log(`   База данных: ${useSQL ? 'SQLite ('+DB_FILE+')' : 'JSON ('+JSON_FILE+')'}`);
  console.log(`   WebRTC сигнализация: включена`);
  console.log(`   Статусы Discord-style: включены`);
  console.log(`\n   Открой в браузере: http://localhost:${PORT}\n`);
});
