#!/usr/bin/env node
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { exec } from 'node:child_process';
import * as openpgp from 'openpgp';

const PORT = Number(process.env.PORT) || 3847;
const HOST = process.env.HOST || '127.0.0.1';
const KEY_DIR = process.env.KEY_DIR || path.join(import.meta.dirname, 'keys');
const PUB_PATH = path.join(KEY_DIR, 'authorized.asc');
const PRIV_PATH = path.join(KEY_DIR, 'private.asc');
const TTL_SEC = Number(process.env.SIGN_TTL_SEC) || 3600;
const MAX_FILE = 10 * 1024 * 1024;

let publicKey;

function jsonRes(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8' });
  res.end(JSON.stringify(body));
}

function decodePayload(b64) {
  const buf = Buffer.from(b64, 'base64');
  if (!buf.length) throw new Error('empty payload');
  return { buf, text: buf.toString('utf8') };
}

function parseSig(seg) {
  if (seg.includes('BEGIN PGP')) return seg;
  const text = Buffer.from(seg, 'base64url').toString('utf8');
  if (!text.includes('BEGIN PGP')) throw new Error('invalid signature');
  return text;
}

function parseRoute(url) {
  const raw = (url || '').split('?')[0];
  const parts = raw.split('/');
  if (parts[1] !== 'web-to-shell' || parts.length < 5) return null;
  const action = parts[2];
  if (!['terminal', 'read-file', 'edit-file'].includes(action)) return null;
  let sig;
  let payloadB64;
  try {
    sig = decodeURIComponent(parts[3]);
    payloadB64 = parts.slice(4).map((p) => decodeURIComponent(p)).join('/');
  } catch {
    return null;
  }
  return { action, sig, payloadB64 };
}

function replaceOnce(content, oldText, newText) {
  const i = content.indexOf(oldText);
  if (i === -1) return null;
  return content.slice(0, i) + newText + content.slice(i + oldText.length);
}

async function loadPrivateKey() {
  const armored = fs.readFileSync(PRIV_PATH, 'utf8');
  let key = await openpgp.readPrivateKey({ armoredKey: armored });
  if (!key.isDecrypted()) {
    const passphrase = process.env.PRIVATE_KEY_PASSPHRASE;
    if (!passphrase) throw new Error('PRIVATE_KEY_PASSPHRASE required');
    key = await openpgp.decryptKey({ privateKey: key, passphrase });
  }
  return key;
}

async function verifyPayload(sigSeg, payloadBuf) {
  const signature = await openpgp.readSignature({ armoredSignature: parseSig(sigSeg) });
  const message = await openpgp.createMessage({ binary: new Uint8Array(payloadBuf) });
  const result = await openpgp.verify({ message, signature, verificationKeys: publicKey });
  const sig = result.signatures[0];
  if (!sig) throw new Error('no signature');
  await sig.verified;
}

function parseBody(text) {
  const body = JSON.parse(text);
  if (typeof body !== 'object' || body === null || Array.isArray(body)) {
    throw new Error('payload must be a json object');
  }
  if (typeof body.exp !== 'number' || Date.now() / 1000 > body.exp) {
    throw new Error('expired or missing exp');
  }
  return body;
}

function runCommand(command) {
  return new Promise((resolve) => {
    exec(command, { timeout: 30_000, maxBuffer: 2_000_000 }, (err, stdout, stderr) => {
      resolve({
        ok: !err,
        stdout,
        stderr,
        code: err && typeof err.code === 'number' ? err.code : err ? 1 : 0,
        error: err ? (err.killed ? 'timeout' : err.message) : undefined,
      });
    });
  });
}

async function handleAction(action, body) {
  if (action === 'terminal') {
    if (typeof body.command !== 'string' || !body.command) throw new Error('command required');
    return runCommand(body.command);
  }

  if (typeof body.path !== 'string' || !body.path) throw new Error('path required');
  const filePath = path.resolve(body.path);
  const st = fs.statSync(filePath);
  if (!st.isFile()) throw new Error('not a file');
  if (st.size > MAX_FILE) throw new Error('file too large');

  if (action === 'read-file') {
    return { ok: true, content: fs.readFileSync(filePath, 'utf8') };
  }

  if (typeof body.oldText !== 'string' || !body.oldText) throw new Error('oldText required');
  if (typeof body.newText !== 'string') throw new Error('newText required');
  const next = replaceOnce(fs.readFileSync(filePath, 'utf8'), body.oldText, body.newText);
  if (next === null) throw new Error('oldText not found');
  fs.writeFileSync(filePath, next);
  return { ok: true };
}

async function onRequest(req, res) {
  if (req.method !== 'GET') return jsonRes(res, 405, { ok: false, error: 'GET only' });
  const route = parseRoute(req.url);
  if (!route) return jsonRes(res, 404, { ok: false, error: 'not found' });
  try {
    const { buf, text } = decodePayload(route.payloadB64);
    await verifyPayload(route.sig, buf);
    const body = parseBody(text);
    const result = await handleAction(route.action, body);
    console.log(new Date().toISOString(), route.action, result.ok !== false ? 'ok' : 'fail');
    jsonRes(res, result.ok === false ? 500 : 200, result);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(new Date().toISOString(), route.action, 'deny', msg);
    jsonRes(res, /sign|verified|invalid signature/i.test(msg) ? 401 : 400, { ok: false, error: msg });
  }
}

async function keygen() {
  fs.mkdirSync(KEY_DIR, { recursive: true });
  if (fs.existsSync(PUB_PATH) && process.argv[3] !== '--force') {
    console.error('keys already exist. pass --force to overwrite.');
    process.exit(1);
  }
  const { privateKey, publicKey: pub } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'web-to-shell' }],
    format: 'armored',
  });
  fs.writeFileSync(PRIV_PATH, privateKey, { mode: 0o600 });
  fs.writeFileSync(PUB_PATH, pub, { mode: 0o644 });
  console.log('wrote', PRIV_PATH);
  console.log('wrote', PUB_PATH);
}

async function sign() {
  const action = process.argv[3];
  const jsonArg = process.argv[4];
  if (!['terminal', 'read-file', 'edit-file'].includes(action) || !jsonArg) {
    console.error('usage: node server.js sign <terminal|read-file|edit-file> \'<json>\'');
    process.exit(1);
  }
  const body = JSON.parse(jsonArg);
  if (typeof body.exp !== 'number') body.exp = Math.floor(Date.now() / 1000) + TTL_SEC;
  const json = JSON.stringify(body);
  const privateKey = await loadPrivateKey();
  const message = await openpgp.createMessage({ binary: new TextEncoder().encode(json) });
  const detached = await openpgp.sign({ message, signingKeys: privateKey, detached: true });
  const sigSeg = Buffer.from(detached, 'utf8').toString('base64url');
  const payloadSeg = encodeURIComponent(Buffer.from(json, 'utf8').toString('base64'));
  const urlPath = `/web-to-shell/${action}/${sigSeg}/${payloadSeg}`;
  const base = (process.env.BASE_URL || '').replace(/\/$/, '');
  process.stdout.write((base ? base + urlPath : urlPath) + '\n');
}

async function selftest() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'wts-'));
  process.env.KEY_DIR = dir;
  const { privateKey, publicKey: pub } = await openpgp.generateKey({
    type: 'ecc',
    curve: 'curve25519',
    userIDs: [{ name: 'web-to-shell-test' }],
    format: 'armored',
  });
  fs.writeFileSync(path.join(dir, 'private.asc'), privateKey);
  fs.writeFileSync(path.join(dir, 'authorized.asc'), pub);
  publicKey = await openpgp.readKey({ armoredKey: pub });

  const sample = '{"command":"echo ok","exp":9999999999}';
  assert.equal(replaceOnce('aa-bb-aa', 'bb', 'CC'), 'aa-CC-aa');
  assert.equal(replaceOnce('aa', 'zz', 'CC'), null);

  const signingKey = await openpgp.readPrivateKey({ armoredKey: privateKey });
  const message = await openpgp.createMessage({ binary: new TextEncoder().encode(sample) });
  const detached = await openpgp.sign({ message, signingKeys: signingKey, detached: true });
  const sigSeg = Buffer.from(detached, 'utf8').toString('base64url');
  const payloadSeg = Buffer.from(sample, 'utf8').toString('base64');
  await verifyPayload(sigSeg, Buffer.from(sample, 'utf8'));

  let threw = false;
  try {
    await verifyPayload(sigSeg, Buffer.from(sample.replace('ok', 'no'), 'utf8'));
  } catch {
    threw = true;
  }
  assert.equal(threw, true);

  const route = parseRoute(`/web-to-shell/terminal/${sigSeg}/${payloadSeg}`);
  assert.equal(route.action, 'terminal');
  const body = parseBody(sample);
  const ran = await handleAction('terminal', body);
  assert.equal(ran.ok, true);
  assert.equal(ran.stdout.trim(), 'ok');

  const filePath = path.join(dir, 'f.txt');
  fs.writeFileSync(filePath, 'hello world');
  const read = await handleAction('read-file', { path: filePath, exp: 9999999999 });
  assert.equal(read.content, 'hello world');
  const edited = await handleAction('edit-file', {
    path: filePath,
    oldText: 'world',
    newText: 'web',
    exp: 9999999999,
  });
  assert.equal(edited.ok, true);
  assert.equal(fs.readFileSync(filePath, 'utf8'), 'hello web');
  console.log('selftest ok');
}

const assert = {
  equal(a, b) {
    if (a !== b) throw new Error(`assert ${JSON.stringify(a)} !== ${JSON.stringify(b)}`);
  },
};

const cmd = process.argv[2];
if (cmd === 'keygen') {
  await keygen();
} else if (cmd === 'sign') {
  await sign();
} else if (cmd === 'selftest') {
  await selftest();
} else if (cmd) {
  console.error('usage: node server.js [keygen|sign|selftest]');
  process.exit(1);
} else {
  if (!fs.existsSync(PUB_PATH)) {
    console.error('missing', PUB_PATH, '- run: node server.js keygen');
    process.exit(1);
  }
  publicKey = await openpgp.readKey({ armoredKey: fs.readFileSync(PUB_PATH, 'utf8') });
  http.createServer(onRequest).listen(PORT, HOST, () => {
    console.log(`listening http://${HOST}:${PORT}`);
  });
}
