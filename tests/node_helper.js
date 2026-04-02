const crypto = require('crypto');
const http = require('http');
const fs = require('fs');
const mode = process.argv[2];
if (mode === 'sign') {
    const sub = process.argv[3] || 'jwt-tester';
    const secret = "super-secret-key-for-jwt-testing-123";
    const header = { alg: "HS256", typ: "JWT" };
    const payload = { iss: "arbit-test-suite", aud: "arbit-users", sub: sub, iat: Math.floor(Date.now()/1000), exp: Math.floor(Date.now()/1000)+3600 };
    const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    const parts = `${b64(header)}.${b64(payload)}`;
    const sig = crypto.createHmac('sha256', secret).update(parts).digest('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
    console.log(`${parts}.${sig}`);
}
if (mode === 'webhook') {
    const server = http.createServer((req, res) => {
        if (req.method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req
.on('end', () => { fs.appendFileSync('webhook.log', body + '
'); res.writeHead(200); res.end('ok'); });
        } else {
            res.writeHead(404);
            res.end();
        }
    });
    server.listen(5000, () => { console.log('Webhook server listening on 5000'); });
}
