#!/usr/bin/env node
const { io } = require('socket.io-client');

const port = Number(process.argv[2] || 9000);
const target = `http://127.0.0.1:${port}`;

function connectClient() {
  return new Promise((resolve, reject) => {
    const client = io(target, {
      transports: ['polling', 'websocket'],
      timeout: 10000,
    });

    const fail = (error) => {
      try { client.close(); } catch {}
      reject(error instanceof Error ? error : new Error(String(error)));
    };

    client.on('connect_error', fail);
    client.on('sync_state', (payload) => {
      if (!payload || !payload.version) {
        fail(new Error('sync_state did not include a version'));
        return;
      }
      client.close();
      resolve(payload);
    });
    client.on('disconnect', (reason) => {
      if (reason !== 'io client disconnect') {
        fail(new Error(`unexpected disconnect: ${reason}`));
      }
    });
  });
}

connectClient()
  .then((payload) => {
    process.stdout.write(JSON.stringify({ success: true, payload }) + '\n');
  })
  .catch((error) => {
    process.stderr.write(JSON.stringify({ success: false, error: error.message }) + '\n');
    process.exit(1);
  });
