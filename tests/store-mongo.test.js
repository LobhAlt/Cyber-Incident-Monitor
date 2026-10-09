'use strict';

/**
 * Exercises the MongoDB storage path against an in-memory stand-in for a
 * collection, so it runs without a database server. Run with: npm test
 */

process.env.NODE_ENV = 'test';
const assert = require('assert');
const store = require('../src/services/store');

function fakeCollection() {
  const docs = new Map();
  let reads = 0;
  return {
    docs,
    get reads() { return reads; },
    async findOne(query) {
      reads += 1;
      const doc = docs.get(query._id);
      return doc ? JSON.parse(JSON.stringify(doc)) : null;
    },
    async replaceOne(query, doc) {
      docs.set(query._id, JSON.parse(JSON.stringify(doc)));
      return { acknowledged: true };
    },
  };
}

let passed = 0;
let failed = 0;
async function test(name, fn) {
  try { await fn(); passed += 1; console.log(`  \x1b[32m✓\x1b[0m ${name}`); } catch (err) {
    failed += 1; console.log(`  \x1b[31m✗\x1b[0m ${name}\n     ${err.message}`);
  }
}

(async function run() {
  console.log('\n  MongoDB storage tests\n');
  const col = fakeCollection();
  store.useMongoCollection(col);

  await test('reports the mongodb backend', () => {
    assert.strictEqual(store.backend(), 'mongodb');
  });

  await test('missing collections read as their defaults', async () => {
    assert.deepStrictEqual(await store.read('users'), []);
    assert.deepStrictEqual(await store.read('settings'), {});
  });

  await test('writes land in the database as one document per collection', async () => {
    await store.write('users', [{ id: 'u1', username: 'riya' }]);
    const doc = col.docs.get('users');
    assert.ok(doc, 'document stored');
    assert.deepStrictEqual(doc.value, [{ id: 'u1', username: 'riya' }]);
  });

  await test('reads are served from memory after the first one', async () => {
    const before = col.reads;
    await store.read('users');
    await store.read('users');
    assert.strictEqual(col.reads, before, 'no extra database reads');
  });

  await test('callers cannot change the cache by mutating what they read', async () => {
    const list = await store.read('users');
    list.push({ id: 'intruder' });
    assert.strictEqual((await store.read('users')).length, 1);
  });

  await test('concurrent updates are serialised, none are lost', async () => {
    await store.write('watchlist', []);
    await Promise.all(Array.from({ length: 25 }, (_, i) => store.update('watchlist', (list) => { list.push(i); return list; })));
    assert.strictEqual((await store.read('watchlist')).length, 25);
    assert.strictEqual(col.docs.get('watchlist').value.length, 25);
  });

  await test('a failed database write leaves the cache unchanged', async () => {
    const original = col.replaceOne;
    col.replaceOne = async () => { throw new Error('network down'); };
    await assert.rejects(store.update('users', (list) => { list.push({ id: 'u2' }); return list; }));
    col.replaceOne = original;
    assert.strictEqual((await store.read('users')).length, 1);
  });

  await test('a mutator that throws writes nothing', async () => {
    await assert.rejects(store.update('users', () => { throw new Error('duplicate'); }));
    assert.strictEqual(col.docs.get('users').value.length, 1);
  });

  console.log(`\n  ${passed} passed, ${failed} failed\n`);
  process.exit(failed === 0 ? 0 : 1);
})();
