// Reference parser for differential testing: Node's HTTP server (llhttp).
// Protocol on stdin:  [4-byte BE length][raw request bytes] ...
// Protocol on stdout: [4-byte BE length][UTF-8 JSON result] ...
// Result: { ok:true, method, target, version, rawHeaders:[name,value,...] }
//      or { ok:false, code, reason }
import http from 'node:http';
import net from 'node:net';

const server = http.createServer();
let current = null; // { id, resolve }
let caseId = 0;

// tag each accepted connection with the case that opened it
server.on('connection', (sock) => { sock._caseId = caseId; });

server.on('request', (req, res) => {
  const rec = {
    ok: true,
    method: req.method,
    target: req.url,
    version: 'HTTP/' + req.httpVersion,
    rawHeaders: req.rawHeaders,
  };
  res.end('ok');
  if (current && req.socket._caseId === current.id) current.resolve(rec);
});
server.on('clientError', (err, socket) => {
  if (current && socket._caseId === current.id) {
    current.resolve({ ok: false, code: err.code || 'ERR', reason: String(err.message || '') });
  }
  try { socket.destroy(); } catch {}
});

await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;

function runCase(buf) {
  return new Promise((resolve) => {
    caseId++;
    const sock = net.connect(port, '127.0.0.1');
    let done = false;
    const finish = (rec) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch {}
      resolve(rec);
    };
    const timer = setTimeout(() => finish({ ok: false, code: 'TIMEOUT', reason: 'no parse result (incomplete request?)' }), 250);
    current = { id: caseId, resolve: finish };
    sock.on('connect', () => sock.write(buf));
    sock.on('error', () => {});
  });
}

let inbuf = Buffer.alloc(0);
process.stdin.on('data', async (chunk) => {
  inbuf = Buffer.concat([inbuf, chunk]);
  for (;;) {
    if (inbuf.length < 4) break;
    const n = inbuf.readUInt32BE(0);
    if (inbuf.length < 4 + n) break;
    const payload = inbuf.subarray(4, 4 + n);
    inbuf = inbuf.subarray(4 + n);
    const rec = await runCase(payload);
    const out = Buffer.from(JSON.stringify(rec), 'utf8');
    const hdr = Buffer.alloc(4);
    hdr.writeUInt32BE(out.length, 0);
    process.stdout.write(Buffer.concat([hdr, out]));
  }
});
