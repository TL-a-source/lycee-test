// server.js
// usage: node server.js

const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

// Si vous mettez derrière un proxy (nginx, etc.) activez trust proxy
app.set('trust proxy', true);

app.use(express.static(path.join(__dirname, 'public'))); // si vous placez index.html dans ./public
app.use(express.json());

const LOG_FILE = path.join(__dirname, 'logs.csv');

// Assurez-vous que le fichier de logs a un en-tête
if (!fs.existsSync(LOG_FILE)) {
  fs.writeFileSync(LOG_FILE, 'id,timestamp,ip_raw,ip,user_agent,referrer,note\n', 'utf8');
}

let nextId = 1;

// utilitaire : récupère IP brute et normalisée
function getClientIp(req) {
  // Priorité X-Forwarded-For (peut contenir plusieurs adresses séparées par des virgules)
  const xff = req.headers['x-forwarded-for'] || req.headers['X-Forwarded-For'] || '';
  const raw = xff ? xff.split(',')[0].trim() : (req.socket.remoteAddress || '');

  let ip = raw || '';

  // Normalisations courantes :
  // - "::ffff:1.2.3.4" -> "1.2.3.4"
  // - "::1" -> "127.0.0.1"
  if (typeof ip === 'string') {
    if (ip.startsWith('::ffff:')) ip = ip.replace('::ffff:', '');
    if (ip === '::1') ip = '127.0.0.1';
    // couper au premier token utile (par sécurité)
    ip = ip.split(/\s/)[0];
  }

  return { raw, ip };
}

app.post('/log', (req, res) => {
  try {
    const { raw: ipRaw, ip } = getClientIp(req);
    const ua = (req.headers['user-agent'] || '').replace(/\n/g, ' ').replace(/"/g, "'");
    const ref = (req.headers['referer'] || req.headers['referrer'] || '').replace(/"/g, "'");
    const note = (req.body && req.body.note) ? String(req.body.note).replace(/,/g, ' ') : '';
    const timestamp = new Date().toISOString();
    const id = nextId++;

    // Enregistre ip_raw (brute) ET ip (normalisée)
    const line = `${id},${timestamp},${ipRaw},${ip},"${ua}","${ref}","${note}"\n`;
    fs.appendFile(LOG_FILE, line, (err) => {
      if (err) {
        console.error('Erreur écriture log:', err);
        return res.status(500).send('erreur écriture');
      }
      // on renvoie ip normalisée pour que le front puisse l'afficher
      res.json({ ok: true, id, timestamp, ip });
    });
  } catch (e) {
    console.error(e);
    res.status(500).send('erreur serveur');
  }
});

// --------- auth simple pour admin (Basic Auth) ----------
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme'; // change pour ton test

function requireBasicAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Admin"');
    return res.status(401).send('Authentification requise');
  }
  const base64 = auth.split(' ')[1];
  const decoded = Buffer.from(base64, 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  res.set('WWW-Authenticate', 'Basic realm="Admin"');
  return res.status(401).send('Identifiants invalides');
}

// Servir la page admin (protégée)
app.get('/admin', requireBasicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API pour lire les logs.csv (protégée)
app.get('/api/logs', requireBasicAuth, (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 50;
  const filter = (req.query.filter || '').toLowerCase();

  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    if (err) return res.status(500).json({ error: 'Impossible de lire les logs' });

    // split lines, ignore header
    const lines = data.split(/\r?\n/).slice(1).filter(Boolean).reverse(); // dernières en premier
    const rows = [];
    for (const line of lines) {
      // CSV: id,timestamp,ip_raw,ip,"ua","ref","note"
      const parts = line.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/).map(p => p.replace(/^"|"$/g, ''));
      const row = {
        id: parts[0] || '',
        timestamp: parts[1] || '',
        ip_raw: parts[2] || '',
        ip: parts[3] || '',
        user_agent: parts[4] || '',
        referrer: parts[5] || '',
        note: parts[6] || ''
      };
      const hay = `${row.ip} ${row.ip_raw} ${row.user_agent} ${row.referrer} ${row.note}`.toLowerCase();
      if (filter && !hay.includes(filter)) continue;
      rows.push(row);
      if (rows.length >= limit) break;
    }
    res.json({ rows });
  });
});

// route de téléchargement direct (protégée)
app.get('/download/logs.csv', requireBasicAuth, (req, res) => {
  res.download(LOG_FILE, 'logs.csv');
});

app.listen(PORT, () => console.log(`Serveur démarré sur http://localhost:${PORT}`));
