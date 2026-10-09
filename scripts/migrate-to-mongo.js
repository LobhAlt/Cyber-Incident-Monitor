'use strict';

/**
 * Copies the local JSON files in data/ into MongoDB, so an existing install
 * keeps its accounts, history and settings after switching to MONGODB_URI.
 *
 *   MONGODB_URI="mongodb+srv://…" npm run migrate:mongo
 *
 * Collections that already exist in the database are left alone unless you
 * add --overwrite. The local session secret is copied too, so people stay
 * signed in.
 */

const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
const config = require('../src/config');
const store = require('../src/services/store');

async function main() {
  if (!config.mongodb.uri) {
    console.error('\n  Set MONGODB_URI first (in .env or on the command line).\n');
    process.exit(1);
  }
  const overwrite = process.argv.includes('--overwrite');
  const { MongoClient } = require('mongodb'); // eslint-disable-line global-require
  const client = new MongoClient(config.mongodb.uri, { serverSelectionTimeoutMS: 15000 });
  await client.connect();
  const collection = client.db(config.mongodb.dbName).collection(store.MONGO_COLLECTION);

  console.log(`\n  Migrating ${config.dataDir} → MongoDB database "${config.mongodb.dbName}"\n`);
  for (const [name, file] of Object.entries(store.FILES)) {
    const full = path.join(config.dataDir, file);
    if (!fs.existsSync(full)) { console.log(`  · ${name}: no local file, skipped`); continue; }
    const existing = await collection.findOne({ _id: name });
    if (existing && !overwrite) { console.log(`  · ${name}: already in the database, kept (use --overwrite to replace)`); continue; }
    const value = JSON.parse(fs.readFileSync(full, 'utf8'));
    await collection.replaceOne({ _id: name }, { _id: name, value, updatedAt: new Date() }, { upsert: true });
    console.log(`  ✓ ${name}: ${Array.isArray(value) ? `${value.length} records` : 'copied'}`);
  }

  const secretFile = path.join(config.dataDir, 'jwt.secret');
  if (!config.jwtSecretFromEnv && fs.existsSync(secretFile)) {
    const secret = fs.readFileSync(secretFile, 'utf8').trim();
    const existing = await collection.findOne({ _id: 'jwtSecret' });
    if (!existing || overwrite) {
      await collection.replaceOne({ _id: 'jwtSecret' }, { _id: 'jwtSecret', value: secret }, { upsert: true });
      console.log('  ✓ session secret copied');
    }
  }

  await client.close();
  console.log('\n  Done.\n');
}

main().catch((err) => {
  console.error(`\n  Migration failed: ${err.message}\n`);
  process.exit(1);
});
