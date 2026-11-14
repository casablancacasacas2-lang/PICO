const express = require('express');
const cors = require('cors');
const path = require('path');
const cron = require('node-cron');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const app = express();
app.use(cors());
app.use(express.json({ limit: '50mb' }));

// FIX (root cause of "applicants keep disappearing at night" even with the
// server never sleeping): NONE of the write endpoints in this file ever had
// any authentication — DELETE /api/applicants (wipes everything),
// DELETE /api/applicants/group/:name, POST /api/applicants/bulk-delete,
// and the /sync endpoint were all wide open to anyone (or anything — bots,
// scanners, crawlers — routinely probe public Render URLs at all hours,
// which lines up with data vanishing overnight with no human at a PC to
// have done it). A shared secret on every state-changing request closes
// this off; both the extension (background.js) and the dashboard
// (public/index.html) send it on every POST/PUT/DELETE to this server via
// the 'x-api-secret' header, patched in once at the top of each of those
// files. Reads (GET) stay open — that's not the actual vulnerability here.
const API_SECRET = process.env.API_SECRET || '06101c3a5f9c59fdf17701a922974dc72ec97c7b2af603b8';
app.use((req, res, next) => {
  if (req.method === 'GET' || req.path === '/api/health') return next();
  if (req.header('x-api-secret') !== API_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
});

// FIX: browsers / mobile carriers / intermediary proxies will happily cache
// a plain GET response that carries no explicit caching headers. That's
// exactly what was causing photos and edited fields (passport no, etc.) to
// look "stuck" on some devices until a hard refresh — the auto-refresh loop
// was firing every 10s, but fetch() was quietly being served a stale cached
// copy instead of hitting the server. Force every /api/* response (data
// changes constantly and must always be fresh) to never be cached.
app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  next();
});

// ===== MongoDB persistence =====
// Render's free plan has no persistent disk and wipes in-memory data on every
// restart/redeploy/sleep-wake cycle. MongoDB Atlas (free tier) keeps the data
// alive across all of that. Set MONGODB_URI in Render → Environment.
// If MONGODB_URI is missing, the server falls back to the old in-memory-only
// behavior (useful for local testing) instead of crashing.
const MONGODB_URI = process.env.MONGODB_URI || '';
const MONGODB_DB = process.env.MONGODB_DB || 'bls_manager';
let db = null;
let mongoReady = false;

// FIX: Added forceSyncTimestamp so extensions can detect when to re-pull
let sharedData = {
  applicants: [],
  groups: [],
  lastModified: new Date().toISOString(),
  forceSyncTimestamp: 0
};

// ===== Profiles store (formerly Firebase Realtime DB) =====
// Used by the Tampermonkey userscript. Keyed by a generated id, same shape
// the script previously got from Firebase: { id1: {...}, id2: {...} }
let profilesData = {};

function generateProfileId() {
  return 'p_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
}

let currentCommand = {
  location: '',
  visaType: '',
  timestamp: Date.now()
};

// ===== Group passwords =====
// Every group can optionally have its own password. Kept as a SEPARATE
// store (not mixed into sharedData.groups, which stays a plain string
// array) so the existing union-merge sync logic never has to change.
// Shape: { [groupName]: { hash, salt, updatedAt } }
let groupAuth = {};

async function saveGroupAuth() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'groupAuth' },
      { $set: { data: groupAuth } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveGroupAuth failed:', e.message);
  }
}

// ===== Activity log =====
// Tracks which PC (deviceId — the same "PC-XXXXXXXXXXXX" serial shown in
// the extension popup) added or overwrote which applicant, and when, so
// the admin dashboard can actually see "which client did what" instead of
// changes silently merging with no trace of the source. Newest first,
// capped so it never grows unbounded.
let activityLog = [];
const MAX_ACTIVITY_LOG = 300;

function nameOf(a) {
  return `${a.FirstName || ''} ${a.LastName || ''}`.trim() || 'Unnamed';
}

function logActivity(entry) {
  activityLog.unshift({ ...entry, timestamp: Date.now() });
  if (activityLog.length > MAX_ACTIVITY_LOG) activityLog.length = MAX_ACTIVITY_LOG;
  saveActivityLog();
}

async function saveActivityLog() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'activityLog' },
      { $set: { data: activityLog } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveActivityLog failed:', e.message);
  }
}

// ===== Device licenses =====
// Every extension install generates its own random deviceId (stored locally
// in chrome.storage). The first time it ever calls /api/license/check it is
// auto-registered here as INACTIVE with no expiry — so a brand-new PC does
// NOT get access until the admin explicitly activates it and sets an expiry
// date from the dashboard. This is the "one license per PC, I control the
// expiry, activate/deactivate button" system.
// Shape: { [deviceId]: { deviceId, label, active, expiresAt (ms|null),
//                          createdAt, lastSeen, lastVersion,
//                          flagged, flagReason, flagCount, lastFlaggedAt,
//                          flaggedFrom (the real/random device id that
//                          reported typing this one in wrong) } }
let licenses = {};

async function saveLicenses() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'licenses' },
      { $set: { data: licenses } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveLicenses failed:', e.message);
  }
}

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { hash, salt };
}

function checkPassword(password, entry) {
  if (!entry) return false;
  const { hash } = hashPassword(password, entry.salt);
  // constant-time compare
  const a = Buffer.from(hash, 'hex');
  const b = Buffer.from(entry.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function generateTempPassword() {
  // Readable but random: e.g. "7F3K-9QRT"
  const part = () => crypto.randomBytes(3).toString('hex').toUpperCase().slice(0, 4);
  return `${part()}-${part()}`;
}

// ===== Password reset =====
// Forgot-password just generates a fresh temporary password and hands it
// straight back in the API response — no email service involved.

// ===== Deletion tombstones =====
// /api/applicants/sync is a merge: any client's local list can push
// records the server doesn't currently have, and they get added back
// (that's needed so a stale client never nukes new applicants it just
// hasn't seen yet). The problem: that same merge doesn't know the
// difference between "this is genuinely new" and "this was deleted
// here, but that client's local copy is stale and doesn't know it".
// So a delete on the dashboard could get silently undone a few
// seconds later by an unrelated tab/extension's next background sync.
//
// Tombstones fix this: every delete records { passportNo: deletedAtMs }.
// A sync only lets an incoming record win over a tombstone if its own
// _updatedAt is genuinely newer than the deletion — i.e. a deliberate
// re-add after the fact — not just an unrefreshed stale copy.
let deletedTombstones = {}; // { [passportNo]: deletedAtMs }

async function saveTombstones() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'tombstones' },
      { $set: { data: deletedTombstones } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveTombstones failed:', e.message);
  }
}

// Records that a passport was just deleted, so sync knows to reject
// stale copies of it. Call this at the moment of every delete.
function tombstone(passportNo) {
  if (passportNo) deletedTombstones[passportNo] = Date.now();
}

// ===== Auto-expiry: applicants are deleted RETENTION_DAYS after creation =====
const RETENTION_DAYS = 20;
const RETENTION_MS = RETENTION_DAYS * 24 * 60 * 60 * 1000;

// Deletes every applicant whose creation date (_createdAt) is >= 20 days old.
// Goes through tombstone() so stale clients can't resurrect them on sync, and
// bumps forceSyncTimestamp so connected extensions re-pull right away.
async function purgeExpiredApplicants() {
  const now = Date.now();
  const expired = sharedData.applicants.filter(a => a._createdAt && now - a._createdAt >= RETENTION_MS);
  if (!expired.length) return 0;
  expired.forEach(a => {
    tombstone(a.PassportNo);
    logActivity({ type: 'expire', deviceId: 'auto-expiry', passportNo: a.PassportNo, name: nameOf(a) });
  });
  const expiredSet = new Set(expired);
  sharedData.applicants = sharedData.applicants.filter(a => !expiredSet.has(a));
  sharedData.lastModified = new Date().toISOString();
  sharedData.forceSyncTimestamp = now;
  await saveSharedData();
  await saveTombstones();
  console.log(`⏳ Auto-expiry: deleted ${expired.length} applicant(s) older than ${RETENTION_DAYS} days`);
  return expired.length;
}

// One-time rollout: gives every record a _createdAt. On the very FIRST run,
// records that are already older than 20 days get a fresh 20-day window
// instead of being wiped the moment this feature is deployed.
async function retentionMigration() {
  const now = Date.now();
  let doc = null;
  if (mongoReady) doc = await db.collection('appstate').findOne({ _id: 'retention' });
  const firstRun = !doc;
  let stamped = 0, graced = 0;
  sharedData.applicants.forEach(a => {
    let base = a._createdAt || a._updatedAt || now;
    if (firstRun && now - base >= RETENTION_MS) { base = now; graced++; }
    if (a._createdAt !== base) { a._createdAt = base; stamped++; }
  });
  if (stamped) await saveSharedData();
  if (mongoReady && firstRun) {
    await db.collection('appstate').updateOne({ _id: 'retention' }, { $set: { migratedAt: now } }, { upsert: true });
  }
  if (stamped || graced) console.log(`⏳ Retention migration: stamped ${stamped}, granted fresh window to ${graced}`);
}

// --- Save helpers: called after every mutation. Each upserts a single
// fixed document per collection, so reads/writes stay as simple as the
// original in-memory version while still persisting to Atlas. ---
async function saveSharedData() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'main' },
      { $set: { ...sharedData } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveSharedData failed:', e.message);
  }
}

async function saveProfiles() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'profiles' },
      { $set: { data: profilesData } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveProfiles failed:', e.message);
  }
}

async function saveCommand() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'command' },
      { $set: { ...currentCommand } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveCommand failed:', e.message);
  }
}

async function connectMongoAndLoad() {
  if (!MONGODB_URI) {
    console.log('⚠️  MONGODB_URI not set — running in-memory only (data will NOT survive restarts)');
    return;
  }
  try {
    const client = new MongoClient(MONGODB_URI);
    await client.connect();
    db = client.db(MONGODB_DB);
    mongoReady = true;
    console.log('🗄️  MongoDB connected —', MONGODB_DB);

    const stateDoc = await db.collection('appstate').findOne({ _id: 'main' });
    if (stateDoc) {
      sharedData = {
        applicants: stateDoc.applicants || [],
        groups: stateDoc.groups || [],
        lastModified: stateDoc.lastModified || new Date().toISOString(),
        forceSyncTimestamp: stateDoc.forceSyncTimestamp || 0
      };
      console.log(`📥 Loaded ${sharedData.applicants.length} applicant(s), ${sharedData.groups.length} group(s) from MongoDB`);
    } else {
      await saveSharedData(); // first run: seed the document
    }

    const profilesDoc = await db.collection('appstate').findOne({ _id: 'profiles' });
    if (profilesDoc) {
      profilesData = profilesDoc.data || {};
      console.log(`📥 Loaded ${Object.keys(profilesData).length} profile(s) from MongoDB`);
    } else {
      await saveProfiles();
    }

    const activityDoc = await db.collection('appstate').findOne({ _id: 'activityLog' });
    if (activityDoc) {
      activityLog = activityDoc.data || [];
      console.log(`📥 Loaded ${activityLog.length} activity log entr(y/ies) from MongoDB`);
    }

    const commandDoc = await db.collection('appstate').findOne({ _id: 'command' });
    if (commandDoc) {
      currentCommand = { location: commandDoc.location || '', visaType: commandDoc.visaType || '', timestamp: commandDoc.timestamp || Date.now() };
    } else {
      await saveCommand();
    }

    const tombstonesDoc = await db.collection('appstate').findOne({ _id: 'tombstones' });
    if (tombstonesDoc) {
      deletedTombstones = tombstonesDoc.data || {};
      console.log(`🪦 Loaded ${Object.keys(deletedTombstones).length} deletion tombstone(s) from MongoDB`);
    } else {
      await saveTombstones();
    }

    await retentionMigration();
    await purgeExpiredApplicants();

    const groupAuthDoc = await db.collection('appstate').findOne({ _id: 'groupAuth' });
    if (groupAuthDoc) {
      groupAuth = groupAuthDoc.data || {};
      console.log(`🔐 Loaded password protection for ${Object.keys(groupAuth).length} group(s) from MongoDB`);
    } else {
      await saveGroupAuth();
    }

    const announcementDoc = await db.collection('appstate').findOne({ _id: 'announcement' });
    if (announcementDoc) {
      announcement = announcementDoc.data || { text: '', color: '#E8FF25', updatedAt: 0 };
      console.log('📢 Loaded announcement banner from MongoDB');
    } else {
      await saveAnnouncement();
    }

    const adminAuthDoc = await db.collection('appstate').findOne({ _id: 'adminAuth' });
    if (adminAuthDoc) {
      adminAuth = adminAuthDoc.data || null;
      console.log(adminAuth ? '🔐 Loaded import master password from MongoDB' : '🔓 No import master password set yet');
    } else {
      await saveAdminAuth();
    }

    const masterAuthDoc = await db.collection('appstate').findOne({ _id: 'masterAuth' });
    if (masterAuthDoc) {
      masterAuth = masterAuthDoc.data || null;
      console.log(masterAuth ? '🗝️  Loaded master override password from MongoDB' : '🗝️  No master override password set yet');
    } else {
      await saveMasterAuth();
    }

    const licensesDoc = await db.collection('appstate').findOne({ _id: 'licenses' });
    if (licensesDoc) {
      licenses = licensesDoc.data || {};
      console.log(`💳 Loaded ${Object.keys(licenses).length} device license(s) from MongoDB`);
    } else {
      await saveLicenses();
    }
  } catch (e) {
    console.error('❌ MongoDB connection failed, falling back to in-memory only:', e.message);
    mongoReady = false;
  }
}

// FIX (root cause of nightly data loss): Render's free plan spins the
// service down after ~15 min with no HTTP traffic — which in practice is
// overnight, when nobody's using the extension. The NEXT request wakes a
// brand-new process, which calls connectMongoAndLoad() exactly once above.
// If THAT ONE connection attempt hits a transient hiccup (Atlas cold TLS
// handshake under a throttled free-tier CPU, a DNS blip, anything
// transient), the old code just logged an error and kept running forever
// with mongoReady=false and sharedData reset to empty — i.e. the dashboard
// shows 0 applicants, indistinguishable from "everything got deleted",
// until someone notices and manually restarts the service. There was no
// retry at all.
//
// Two independent fixes:
//   1) Retry the *initial* connection a few times with backoff instead of
//      giving up after one attempt — covers most transient cold-start
//      failures immediately.
//   2) A standing watchdog that keeps trying every 2 minutes for as long as
//      mongoReady is false — covers the rarer case where even the retried
//      attempts above all failed (e.g. Atlas itself was briefly down), so
//      the service self-heals on its own instead of needing a manual
//      restart the next morning.
async function connectMongoWithRetry(maxAttempts = 5) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    await connectMongoAndLoad();
    if (mongoReady || !MONGODB_URI) return;
    const waitMs = Math.min(2000 * 2 ** (attempt - 1), 30000); // 2s,4s,8s,16s,30s
    console.log(`⏳ Mongo connect attempt ${attempt}/${maxAttempts} failed — retrying in ${waitMs / 1000}s`);
    await new Promise(r => setTimeout(r, waitMs));
  }
  if (!mongoReady) {
    console.error('❌ All initial MongoDB connection attempts failed — starting in-memory-only. The watchdog below will keep trying to recover automatically.');
  }
}

setInterval(() => {
  if (!mongoReady && MONGODB_URI) {
    console.log('🔁 Mongo watchdog: still disconnected, retrying...');
    connectMongoAndLoad();
  }
}, 2 * 60 * 1000);

app.use(express.static(path.join(__dirname, 'public')));


app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', applicants: sharedData.applicants.length, groups: sharedData.groups.length });
});

// Returns full shared data including forceSyncTimestamp (used by extensions)
app.get('/api/applicants', async (req, res) => {
  await purgeExpiredApplicants();
  res.json(sharedData);
});

// Recent add/overwrite history, attributed by deviceId (the "PC-XXXX..."
// serial shown in the extension popup) — powers the dashboard's activity
// log panel. ?limit= caps how many entries come back (default 50).
app.get('/api/activity-log', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit, 10) || 50, MAX_ACTIVITY_LOG);
  res.json({ entries: activityLog.slice(0, limit) });
});

// FIX: MERGE instead of overwrite - the root cause fix
// Incoming applicants are upserted by PassportNo.
// Applicants already on server but NOT in payload are KEPT (not deleted).
// Conflict resolution: _updatedAt timestamp decides winner.
app.post('/api/applicants/sync', async (req, res) => {
  const { applicants, groups, deviceId: syncDeviceId } = req.body;
  if (!Array.isArray(applicants)) return res.status(400).json({ error: 'Invalid: applicants must be an array' });
  const actor = syncDeviceId || 'unknown device';

  // FIX: normalize the key (trim whitespace) so a passport number that picked up
  // stray spaces from autofill/scraping doesn't get treated as a different record
  const normKey = (p) => (p || '').trim();

  // Build map of current server applicants
  const serverMap = new Map(sharedData.applicants.map(a => [normKey(a.PassportNo), a]));

  let autoKeyedCount = 0;
  for (const incoming of applicants) {
    let key = normKey(incoming.PassportNo);
    // FIX: don't silently drop applicants who don't have a passport number
    // yet (e.g. added before that field was filled in). Dropping them here
    // meant the client's own "✅ Imported!" success message was a lie —
    // the entry would vanish the moment the next sync response overwrote
    // local storage. Instead, give it a temporary unique key so it
    // round-trips through the server like any other record; once a real
    // PassportNo is entered later, normal upsert-by-PassportNo takes over.
    if (!key) {
      key = `NOPASSPORT-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
      autoKeyedCount++;
    }

    const incomingTime = incoming._updatedAt || 0;

    // If this passport was deleted here, only let the incoming record
    // win if it's genuinely newer than the deletion (a deliberate
    // re-add). Otherwise it's just a stale client that hasn't caught
    // up with the delete yet — drop it, don't resurrect the record.
    //
    // FIX: an explicit Import/restore from a backup file (popup.js sets
    // `_forceRestore: true` on every record it imports) is a deliberate,
    // conscious user action — it must always win over a tombstone, even
    // if the incoming _updatedAt doesn't come out strictly newer than
    // deletedAt (e.g. the PC's clock is behind the server's, or the
    // import happens within the same millisecond as an unrelated
    // deletion). Without this, the import silently "succeeds" locally
    // (popup.js shows ✅) but the very next pushToAPI()/pull overwrites
    // local storage with the server's copy, which never actually saved
    // the restored record — so it disappears again with no error shown.
    const deletedAt = deletedTombstones[key];
    if (deletedAt) {
      if (!incoming._forceRestore && incomingTime <= deletedAt) continue;
      delete deletedTombstones[key]; // deliberate restore/newer edit supersedes the tombstone
    }
    const wasForceRestore = !!incoming._forceRestore;
    if (incoming._forceRestore) delete incoming._forceRestore; // transient flag, not part of stored data

    const existing = serverMap.get(key);

    if (!existing) {
      // New applicant — always add
      serverMap.set(key, {
        ...incoming,
        PassportNo: key,
        // a deliberate restore starts a fresh 20-day window (an old backup
        // would otherwise be auto-deleted again within minutes)
        _createdAt: wasForceRestore ? Date.now() : (incoming._createdAt || Date.now()),
        _updatedAt: incoming._updatedAt || Date.now()
      });
      logActivity({ type: 'add', deviceId: actor, passportNo: key, name: nameOf(incoming) });
    } else {
      // Both sides have this passport: keep the more recently updated one
      const existingTime = existing._updatedAt  || 0;
      if (incomingTime >= existingTime) {
        // Only log a real overwrite, not an identical record being
        // re-pushed (which happens constantly on routine auto-syncs) —
        // otherwise the log would be flooded with meaningless noise.
        const isRealChange = JSON.stringify({ ...existing, _updatedAt: 0 }) !==
          JSON.stringify({ ...incoming, PassportNo: key, _updatedAt: 0 });
        if (isRealChange) {
          logActivity({ type: 'update', deviceId: actor, passportNo: key, name: nameOf(incoming) });
        }
        serverMap.set(key, {
          ...incoming,
          PassportNo: key,
          // creation date is never reset by edits/re-syncs
          _createdAt: wasForceRestore ? Date.now() : (existing._createdAt || incoming._createdAt || Date.now()),
          _updatedAt: incomingTime || Date.now()
        });
      }
      // else: server version is newer — keep it, discard incoming
    }
  }

  sharedData.applicants = Array.from(serverMap.values());
  await purgeExpiredApplicants();

  // Merge groups (union — never remove a group because a stale client didn't have it)
  const allGroups = new Set([...sharedData.groups, ...(groups || [])]);
  sharedData.groups = Array.from(allGroups);
  sharedData.lastModified = new Date().toISOString();
  await saveSharedData();
  await saveTombstones();

  res.json({
    success: true,
    data: sharedData,
    stats: {
      totalApplicants: sharedData.applicants.length,
      totalGroups: sharedData.groups.length,
      autoKeyedNoPassport: autoKeyedCount // how many incoming records had no PassportNo and got a temporary key
    }
  });
});

// FIX: Atomic edit — updates the ONE record matching the original passport number.
// Unlike /api/applicants/sync (a full-list merge), this can never create a duplicate,
// even if the passport number field itself is being changed as part of the edit,
// and even if another client's stale full-list sync races with it.
app.put('/api/applicants/:passportNo', async (req, res) => {
  const originalPassportNo = decodeURIComponent(req.params.passportNo).trim();
  const updated = req.body;

  if (!updated || !updated.PassportNo || !updated.PassportNo.trim()) {
    return res.status(400).json({ error: 'PassportNo is required in the request body' });
  }

  const newPassportNo = updated.PassportNo.trim();

  // Block silently merging into a different existing applicant if the new
  // passport number collides with someone else's record
  const clash = sharedData.applicants.find(
    a => a.PassportNo === newPassportNo && a.PassportNo !== originalPassportNo
  );
  if (clash) {
    return res.status(409).json({ error: `Passport ${newPassportNo} is already used by another applicant` });
  }

  const idx = sharedData.applicants.findIndex(a => a.PassportNo === originalPassportNo);
  // deviceId here is just attribution for the activity log, not a real
  // applicant field — keep it out of what actually gets stored.
  const { deviceId: editorDeviceId, ...updatedFields } = updated;
  const prevCreatedAt = idx >= 0 ? sharedData.applicants[idx]._createdAt : null;
  const record = { ...updatedFields, PassportNo: newPassportNo, _createdAt: prevCreatedAt || updatedFields._createdAt || Date.now(), _updatedAt: Date.now() };

  if (idx >= 0) {
    sharedData.applicants[idx] = record; // update the exact record in place
    logActivity({ type: 'update', deviceId: editorDeviceId || 'Admin Dashboard', passportNo: newPassportNo, name: nameOf(record) });
  } else {
    sharedData.applicants.push(record); // original wasn't found — add it rather than lose the edit
    logActivity({ type: 'add', deviceId: editorDeviceId || 'Admin Dashboard', passportNo: newPassportNo, name: nameOf(record) });
  }

  // Deliberate action via the dashboard — clear any tombstone so a
  // later sync doesn't second-guess this intentional (re-)add.
  delete deletedTombstones[originalPassportNo];
  delete deletedTombstones[newPassportNo];

  if (record.group && !sharedData.groups.includes(record.group)) {
    sharedData.groups.push(record.group);
  }
  sharedData.lastModified = new Date().toISOString();
  await saveSharedData();
  await saveTombstones();

  res.json({ success: true, data: sharedData });
});

// ===== Master override password =====
// A single "skeleton key" password that always works as a valid password
// for ANY group AND for the import password — a backup/reset path for
// when a specific group's password is forgotten and email isn't handy.
let masterAuth = null; // { hash, salt, updatedAt } | null

async function saveMasterAuth() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'masterAuth' },
      { $set: { data: masterAuth } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveMasterAuth failed:', e.message);
  }
}

// Checks a submitted password against a specific entry OR the master
// override password, whichever matches.
function checkPasswordOrMaster(password, entry) {
  if (checkPassword(password, entry)) return true;
  if (masterAuth && checkPassword(password, masterAuth)) return true;
  return false;
}

// Gate for sensitive admin-only routes (Device Licenses panel). Reuses the
// same admin/master password as Import — set once from the 🔑 button — so
// there's a single password to remember. If no admin password has ever been
// set, these routes are blocked outright rather than silently left open,
// since this panel controls who gets to use the product at all.
function requireAdminPassword(req, res, next) {
  if (!adminAuth) {
    return res.status(401).json({ error: 'admin_password_not_set', message: 'Set an admin password from the dashboard (🔑 button) before Licenses can be used.' });
  }
  const pwd = req.get('x-admin-password') || (req.body && req.body.adminPassword) || req.query.adminPassword;
  if (!checkPasswordOrMaster(pwd || '', adminAuth)) {
    return res.status(403).json({ error: 'invalid_admin_password' });
  }
  next();
}

app.get('/api/master/protected', (req, res) => {
  res.json({ protected: !!masterAuth });
});

app.post('/api/master/password', async (req, res) => {
  const { password, currentPassword } = req.body || {};
  if (!password || String(password).trim().length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  if (masterAuth && !checkPassword(currentPassword || '', masterAuth)) {
    return res.status(403).json({ error: 'Current master password is incorrect' });
  }
  masterAuth = { ...hashPassword(password), updatedAt: Date.now() };
  await saveMasterAuth();
  res.json({ success: true });
});

// FIX: this used to hand the new password straight back in the response —
// anyone could call it, no verification at all. Now it's sent instead to
// the phone number configured in CALLMEBOT_PHONE (same WhatsApp integration
// used for the hourly change notification) — only whoever has that phone
// ever sees the new password. If CALLMEBOT_PHONE/CALLMEBOT_APIKEY aren't
// set on Render, this is refused rather than falling back to exposing it.
app.post('/api/master/forgot-password', async (req, res) => {
  if (!masterAuth) return res.status(404).json({ error: 'No master password is set' });
  if (!process.env.CALLMEBOT_PHONE || !process.env.CALLMEBOT_APIKEY) {
    return res.status(503).json({ error: 'no_phone_configured', message: 'CALLMEBOT_PHONE/CALLMEBOT_APIKEY must be set on the server for phone-verified reset.' });
  }
  const newPassword = generateTempPassword();
  const sent = await sendWhatsAppNotification(`🔑 New MASTER password: ${newPassword}`);
  if (!sent) return res.status(502).json({ error: 'whatsapp_send_failed' });
  masterAuth = { ...hashPassword(newPassword), updatedAt: Date.now() };
  await saveMasterAuth();
  res.json({ success: true, sentToPhone: true });
});

app.delete('/api/master/password', async (req, res) => {
  const { password } = req.body || {};
  if (masterAuth && !checkPassword(password || '', masterAuth)) {
    return res.status(403).json({ error: 'Current master password is incorrect' });
  }
  masterAuth = null;
  await saveMasterAuth();
  res.json({ success: true });
});

// ===== Admin master password (protects Import) =====
// A single global password, separate from per-group passwords — Import
// can touch every group at once, so it needs its own gate.
let adminAuth = null; // { hash, salt, updatedAt } | null

async function saveAdminAuth() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'adminAuth' },
      { $set: { data: adminAuth } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveAdminAuth failed:', e.message);
  }
}

app.get('/api/admin/protected', (req, res) => {
  res.json({ protected: !!adminAuth });
});

app.post('/api/admin/password', async (req, res) => {
  const { password, currentPassword } = req.body || {};
  if (!password || String(password).trim().length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  if (adminAuth && !checkPasswordOrMaster(currentPassword || '', adminAuth)) {
    return res.status(403).json({ error: 'Current password is incorrect' });
  }
  adminAuth = { ...hashPassword(password), updatedAt: Date.now() };
  await saveAdminAuth();
  res.json({ success: true });
});

app.post('/api/admin/verify', (req, res) => {
  const { password } = req.body || {};
  if (!adminAuth) return res.json({ ok: true, protected: false });
  res.json({ ok: checkPasswordOrMaster(password || '', adminAuth), protected: true });
});

// Same phone-verified reset as master password above — see comment there.
app.post('/api/admin/forgot-password', async (req, res) => {
  if (!adminAuth) return res.status(404).json({ error: 'No import password is set' });
  if (!process.env.CALLMEBOT_PHONE || !process.env.CALLMEBOT_APIKEY) {
    return res.status(503).json({ error: 'no_phone_configured', message: 'CALLMEBOT_PHONE/CALLMEBOT_APIKEY must be set on the server for phone-verified reset.' });
  }
  const newPassword = generateTempPassword();
  const sent = await sendWhatsAppNotification(`🔑 New admin/import password: ${newPassword}`);
  if (!sent) return res.status(502).json({ error: 'whatsapp_send_failed' });
  adminAuth = { ...hashPassword(newPassword), updatedAt: Date.now() };
  await saveAdminAuth();
  res.json({ success: true, sentToPhone: true });
});

app.delete('/api/admin/password', async (req, res) => {
  const { password } = req.body || {};
  if (adminAuth && !checkPasswordOrMaster(password || '', adminAuth)) {
    return res.status(403).json({ error: 'Current password is incorrect' });
  }
  adminAuth = null;
  await saveAdminAuth();
  res.json({ success: true });
});

// ===== Announcement banner =====
// A single admin-authored message shown as a banner across the top of the
// dashboard for everyone who has it open (picked up by their normal
// 10-second poll — no extra infrastructure needed).
let announcement = { text: '', color: '#E8FF25', updatedAt: 0 };

async function saveAnnouncement() {
  if (!mongoReady) return;
  try {
    await db.collection('appstate').updateOne(
      { _id: 'announcement' },
      { $set: { data: announcement } },
      { upsert: true }
    );
  } catch (e) {
    console.error('⚠️  Mongo saveAnnouncement failed:', e.message);
  }
}

app.get('/api/announcement', (req, res) => {
  res.json(announcement);
});

app.post('/api/announcement', async (req, res) => {
  const text = String((req.body || {}).text || '').trim();
  const colorInput = String((req.body || {}).color || '').trim();
  const color = /^#[0-9A-Fa-f]{6}$/.test(colorInput) ? colorInput : (announcement.color || '#E8FF25');
  announcement = { text, color, updatedAt: Date.now() };
  await saveAnnouncement();
  res.json({ success: true, announcement });
});

app.delete('/api/announcement', async (req, res) => {
  announcement = { text: '', color: announcement.color || '#E8FF25', updatedAt: Date.now() };
  await saveAnnouncement();
  res.json({ success: true });
});

// ===== Device licensing =====
// Called by the extension itself (background.js) — every install checks in
// with its own randomly-generated deviceId. Brand-new devices are
// auto-registered here as INACTIVE so they need an explicit admin activation
// before the extension will do anything.
app.post('/api/license/check', async (req, res) => {
  const { deviceId, instanceId, claim, label, version } = req.body || {};
  const id = String(deviceId || '').trim();
  if (!id) return res.status(400).json({ error: 'deviceId is required' });
  const instId = instanceId ? String(instanceId).trim() : '';

  const now = Date.now();
  let entry = licenses[id];
  if (!entry) {
    entry = {
      deviceId: id,
      label: (label ? String(label).trim() : '').slice(0, 80) || 'New device',
      active: false,
      expiresAt: null,
      createdAt: now,
      lastSeen: now,
      lastVersion: version || '',
      activeInstanceId: instId || null,
      activeInstanceSeenAt: instId ? now : null,
      instanceSwitches: 0
    };
    licenses[id] = entry;
    console.log(`💳 New device checked in (awaiting activation): ${id}`);
  } else {
    entry.lastSeen = now;
    if (version) entry.lastVersion = version;

    if (instId) {
      // Multi-browser mode: this serial is allowed to be used from any
      // number of browsers/profiles on the PC it was activated for, at
      // the same time, with no re-activation needed per browser and no
      // auto-lockout when a second/third Chrome checks in with it.
      // We still remember the most recent instance for visibility in the
      // admin dashboard, but it's informational only now.
      entry.activeInstanceId = instId;
      entry.activeInstanceSeenAt = now;
    }
  }
  await saveLicenses();

  const expired = entry.expiresAt != null && entry.expiresAt < now;
  const valid = !!entry.active && !expired;
  let reason = !entry.active ? 'inactive' : expired ? 'expired' : 'ok';
  if (!entry.active && entry.flagged && entry.flagReason === 'used_on_another_device') {
    reason = 'used_on_another_device';
  }

  res.json({
    valid,
    active: entry.active,
    expiresAt: entry.expiresAt,
    reason,
    label: entry.label
  });
});

// Called by the extension when someone pastes/types a device serial that
// doesn't match the expected format (i.e. they typed the PC's number in
// wrong). We register the mistyped id as an auto-blocked ("flagged") entry
// — it stays inactive so it can never be used even if someone later
// stumbles onto that exact string — and the admin dashboard surfaces it
// so the admin gets a visible signal.
app.post('/api/license/flag', async (req, res) => {
  const { attemptedId, realDeviceId, reason, version } = req.body || {};
  const id = String(attemptedId || '').trim().toUpperCase();
  if (!id) return res.status(400).json({ error: 'attemptedId is required' });

  const now = Date.now();
  let entry = licenses[id];
  if (!entry) {
    entry = {
      deviceId: id,
      label: 'Invalid serial attempt',
      active: false,
      expiresAt: null,
      createdAt: now,
      lastSeen: now,
      lastVersion: version || ''
    };
    licenses[id] = entry;
  } else {
    entry.lastSeen = now;
    entry.active = false; // force-block: an id that failed format validation is never usable
  }

  entry.flagged = true;
  entry.flagReason = String(reason || 'invalid_format').slice(0, 120);
  entry.flagCount = (entry.flagCount || 0) + 1;
  entry.lastFlaggedAt = now;
  if (realDeviceId) entry.flaggedFrom = String(realDeviceId).trim().slice(0, 120);

  await saveLicenses();
  console.log(`🚩 Flagged invalid device serial attempt: ${id} (${entry.flagCount}x)`);

  res.json({ success: true, license: entry });
});

// Admin: how many devices are currently flagged (unresolved), for a quick
// badge/signal in the dashboard without opening the full Licenses panel.
app.get('/api/admin/licenses/flags-count', requireAdminPassword, (req, res) => {
  const count = Object.values(licenses).filter(l => l.flagged).length;
  res.json({ count });
});

// Admin: list every known device license.
app.get('/api/admin/licenses', requireAdminPassword, (req, res) => {
  res.json({ licenses: Object.values(licenses).sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0)) });
});

// Admin: create/update a device's license (label, active flag, expiry date).
// Also usable to hand-register a device that hasn't checked in yet.
app.post('/api/admin/licenses/:deviceId', requireAdminPassword, async (req, res) => {
  const id = decodeURIComponent(req.params.deviceId);
  const { label, active, expiresAt, flagged, resetInstance } = req.body || {};
  const now = Date.now();

  let entry = licenses[id];
  if (!entry) {
    entry = { deviceId: id, label: '', active: false, expiresAt: null, createdAt: now, lastSeen: null, lastVersion: '' };
    licenses[id] = entry;
  }
  if (typeof label === 'string') entry.label = label.trim().slice(0, 80);
  if (typeof active === 'boolean') {
    entry.active = active;
    // Reactivating is the admin's way of resolving an "unauthorized device"
    // block — clear the flag unless they also explicitly set it below.
    if (active && entry.flagReason === 'used_on_another_device' && flagged === undefined) {
      entry.flagged = false;
    }
  }
  if (expiresAt === null) entry.expiresAt = null;
  else if (expiresAt !== undefined) {
    const t = Number(expiresAt);
    entry.expiresAt = Number.isFinite(t) ? t : entry.expiresAt;
  }
  if (typeof flagged === 'boolean') entry.flagged = flagged; // admin dismissing/re-raising a flag
  if (resetInstance) {
    // Release the lock instead of restoring the original device — whichever
    // browser/PC claims this serial next becomes the new authorized owner.
    entry.activeInstanceId = null;
    entry.activeInstanceSeenAt = null;
  }

  await saveLicenses();
  res.json({ success: true, license: entry });
});

// Admin: delete a device's license entirely (it will re-register as
// inactive the next time that device checks in).
app.delete('/api/admin/licenses/:deviceId', requireAdminPassword, async (req, res) => {
  const id = decodeURIComponent(req.params.deviceId);
  delete licenses[id];
  await saveLicenses();
  res.json({ success: true });
});

// ===== Group password endpoints =====

// Which groups currently have a password set (names only — never hashes).
// The dashboard fetches this once so it knows when to prompt for a password.
app.get('/api/groups/protected', (req, res) => {
  res.json({ protected: Object.keys(groupAuth) });
});

// Set a group's password. If the group has NO password yet, this works
// with no auth (that's how it gets set the first time, right after the
// group is created). If it already has one, the caller must include the
// correct current password — otherwise use /forgot-password instead.
app.post('/api/groups/:name/password', async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  const { password, currentPassword } = req.body || {};
  if (!password || String(password).trim().length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters' });
  }
  const existing = groupAuth[name];
  if (existing && !checkPasswordOrMaster(currentPassword || '', existing)) {
    return res.status(403).json({ error: 'Current password is incorrect' });
  }
  groupAuth[name] = { ...hashPassword(password), updatedAt: Date.now() };
  await saveGroupAuth();
  res.json({ success: true });
});

// Verify a group's password (used to unlock viewing/editing/deleting a
// protected group in the dashboard). Groups with no password set always
// verify as true (nothing to check).
app.post('/api/groups/:name/verify', (req, res) => {
  const name = decodeURIComponent(req.params.name);
  const { password } = req.body || {};
  const entry = groupAuth[name];
  if (!entry) return res.json({ ok: true, protected: false });
  res.json({ ok: checkPasswordOrMaster(password || '', entry), protected: true });
});

// Same phone-verified reset as master/admin above — see comment there.
app.post('/api/groups/:name/forgot-password', async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  if (!groupAuth[name]) {
    return res.status(404).json({ error: 'This group has no password set' });
  }
  if (!process.env.CALLMEBOT_PHONE || !process.env.CALLMEBOT_APIKEY) {
    return res.status(503).json({ error: 'no_phone_configured', message: 'CALLMEBOT_PHONE/CALLMEBOT_APIKEY must be set on the server for phone-verified reset.' });
  }
  const newPassword = generateTempPassword();
  const sent = await sendWhatsAppNotification(`🔑 New password for group "${name}": ${newPassword}`);
  if (!sent) return res.status(502).json({ error: 'whatsapp_send_failed' });
  groupAuth[name] = { ...hashPassword(newPassword), updatedAt: Date.now() };
  await saveGroupAuth();
  res.json({ success: true, sentToPhone: true });
});

// Remove password protection from a group entirely (requires current password).
app.delete('/api/groups/:name/password', async (req, res) => {
  const name = decodeURIComponent(req.params.name);
  const { password } = req.body || {};
  const existing = groupAuth[name];
  if (existing && !checkPasswordOrMaster(password || '', existing)) {
    return res.status(403).json({ error: 'Current password is incorrect' });
  }
  delete groupAuth[name];
  await saveGroupAuth();
  res.json({ success: true });
});

// FIX: Atomic group delete — safe, doesn't require client to send full applicant list
app.delete('/api/applicants/group/:groupName', async (req, res) => {
  const groupName = decodeURIComponent(req.params.groupName);
  sharedData.applicants
    .filter(a => a.group === groupName)
    .forEach(a => tombstone(a.PassportNo));
  sharedData.applicants = sharedData.applicants.filter(a => a.group !== groupName);
  sharedData.groups     = sharedData.groups.filter(g => g !== groupName);
  sharedData.lastModified = new Date().toISOString();
  delete groupAuth[groupName];
  await saveGroupAuth();
  await saveSharedData();
  await saveTombstones();
  res.json({ success: true, data: sharedData });
});

// FIX: Atomic single-applicant delete by passport number
app.delete('/api/applicants/:passportNo', async (req, res) => {
  const passportNo = decodeURIComponent(req.params.passportNo);
  tombstone(passportNo);
  sharedData.applicants = sharedData.applicants.filter(a => a.PassportNo !== passportNo);
  sharedData.lastModified = new Date().toISOString();
  await saveSharedData();
  await saveTombstones();
  res.json({ success: true, data: sharedData });
});

// Bulk delete — removes every applicant whose PassportNo is in the given
// list in one atomic pass. Used by the dashboard's checkbox multi-select +
// "Delete selected" button, so selecting 20 clients doesn't fire 20
// separate requests.
app.post('/api/applicants/bulk-delete', async (req, res) => {
  const { passportNumbers } = req.body;
  if (!Array.isArray(passportNumbers) || passportNumbers.length === 0) {
    return res.status(400).json({ error: 'passportNumbers must be a non-empty array' });
  }
  const toDelete = new Set(passportNumbers);
  toDelete.forEach(p => tombstone(p));
  sharedData.applicants = sharedData.applicants.filter(a => !toDelete.has(a.PassportNo));
  sharedData.lastModified = new Date().toISOString();
  await saveSharedData();
  await saveTombstones();
  res.json({ success: true, data: sharedData });
});

// Delete ALL applicants
app.delete('/api/applicants', async (req, res) => {
  sharedData.applicants.forEach(a => tombstone(a.PassportNo));
  sharedData = {
    applicants: [],
    groups: [],
    lastModified: new Date().toISOString(),
    forceSyncTimestamp: sharedData.forceSyncTimestamp // preserve so extensions don't re-trigger
  };
  await saveSharedData();
  await saveTombstones();
  res.json({ success: true });
});

// FIX: Force sync endpoint — sets forceSyncTimestamp so polling extensions re-pull
app.post('/api/force-sync', async (req, res) => {
  sharedData.forceSyncTimestamp = Date.now();
  await saveSharedData();
  console.log('📢 Force sync triggered at', new Date().toISOString());
  res.json({ success: true, timestamp: sharedData.forceSyncTimestamp });
});

app.post('/api/broadcast', async (req, res) => {
  const { location, visaType, timestamp } = req.body;
  if (!location || !visaType) {
    return res.status(400).json({ success: false, error: 'Missing location or visaType' });
  }
  currentCommand = { location, visaType, timestamp: timestamp || Date.now() };
  await saveCommand();
  console.log('📢 Broadcast:', currentCommand);
  res.json({ success: true, command: currentCommand });
});

app.get('/api/broadcast', (req, res) => {
  res.json({ success: true, ...currentCommand });
});

// ===== Profiles endpoints (replaces Firebase for the Tampermonkey userscript) =====

// GET all profiles -> { id: {...}, id: {...} } (empty object if none)
app.get('/api/profiles', (req, res) => {
  res.json(profilesData);
});

// POST a new profile -> server generates the id (like Firebase push)
app.post('/api/profiles', async (req, res) => {
  const id = generateProfileId();
  profilesData[id] = { ...req.body };
  await saveProfiles();
  res.json({ success: true, id, name: id });
});

// PUT (create-or-replace) a profile at a specific id
app.put('/api/profiles/:id', async (req, res) => {
  const { id } = req.params;
  profilesData[id] = { ...req.body };
  await saveProfiles();
  res.json({ success: true, id });
});

// DELETE a single profile
app.delete('/api/profiles/:id', async (req, res) => {
  const { id } = req.params;
  delete profilesData[id];
  await saveProfiles();
  res.json({ success: true, id });
});

// DELETE all profiles
app.delete('/api/profiles', async (req, res) => {
  profilesData = {};
  await saveProfiles();
  res.json({ success: true });
});

// ===== Full export + hourly WhatsApp notification (CallMeBot) =====
//
// GET /api/export/full — always-current JSON download of everything
// (applicants + groups), served as an attachment so it can be linked
// straight from a WhatsApp message.
app.get('/api/export/full', (req, res) => {
  const filename = `bls-applicants-${new Date().toISOString().split('T')[0]}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.json({
    applicants: sharedData.applicants,
    groups: sharedData.groups,
    exportedAt: new Date().toISOString()
  });
});

// CallMeBot (https://www.callmebot.com/blog/free-api-whatsapp-messages/) —
// a free personal-use WhatsApp API: you message their bot once to get an
// apikey, then this server can text that same WhatsApp number. It only
// sends TEXT, not file attachments, so the hourly message is a short
// summary + a link back to /api/export/full for the actual file.
//
// Configure via environment variables (Render → Environment):
//   CALLMEBOT_PHONE   — your WhatsApp number, international format, no "+" (e.g. 2126xxxxxxxx)
//   CALLMEBOT_APIKEY  — the apikey CallMeBot gave you
//   PUBLIC_BASE_URL   — this server's public URL (e.g. https://manage-2027.onrender.com)
// If any of these are missing, the hourly check still runs but just logs
// and skips sending, instead of crashing.
//
// NOTE: Render's free web services spin down after ~15 min of no HTTP
// traffic. That would silently break this hourly cron. Keep the service
// awake for free by pointing an external pinger (e.g. cron-job.org or
// UptimeRobot, both free) at GET /api/health every 10 minutes.
let lastNotifiedModified = null;

async function sendWhatsAppNotification(text) {
  const phone = process.env.CALLMEBOT_PHONE;
  const apikey = process.env.CALLMEBOT_APIKEY;
  if (!phone || !apikey) {
    console.log('⚠️  WhatsApp notify skipped — CALLMEBOT_PHONE/CALLMEBOT_APIKEY not set');
    return false;
  }
  const url = `https://api.callmebot.com/whatsapp.php?phone=${encodeURIComponent(phone)}&text=${encodeURIComponent(text)}&apikey=${encodeURIComponent(apikey)}`;
  try {
    const r = await fetch(url);
    console.log('📲 WhatsApp notify sent, status', r.status);
    return true;
  } catch (e) {
    console.error('📲 WhatsApp notify failed:', e.message);
    return false;
  }
}

// Runs at the top of every hour. Only sends a message if the data has
// actually changed (sharedData.lastModified) since the last time it sent
// one — so an idle hour with no edits stays silent.
cron.schedule('0 * * * *', async () => {
  // Prune tombstones older than 30 days — by then no realistic stale
  // client sync is still carrying that old a snapshot, so there's no
  // more resurrection risk and they'd just grow the DB forever.
  const THIRTY_DAYS_MS = 30 * 24 * 60 * 60 * 1000;
  const cutoff = Date.now() - THIRTY_DAYS_MS;
  let pruned = 0;
  for (const [passportNo, deletedAt] of Object.entries(deletedTombstones)) {
    if (deletedAt < cutoff) { delete deletedTombstones[passportNo]; pruned++; }
  }
  if (pruned) {
    await saveTombstones();
    console.log(`🪦 Pruned ${pruned} tombstone(s) older than 30 days`);
  }

  if (sharedData.lastModified === lastNotifiedModified) {
    console.log('⏰ Hourly check: no changes since last notification, skipping');
    return;
  }
  const base = process.env.PUBLIC_BASE_URL || '';
  const downloadLine = base ? `\nDownload: ${base}/api/export/full` : '';
  const text = `📋 BLS Applicant Manager — update\n` +
    `${sharedData.applicants.length} applicant(s), ${sharedData.groups.length} group(s)\n` +
    `Last change: ${sharedData.lastModified}${downloadLine}`;
  await sendWhatsAppNotification(text);
  lastNotifiedModified = sharedData.lastModified;
});

// Auto-expiry check every 5 minutes (also runs on every sync / pull)
cron.schedule('*/5 * * * *', () => { purgeExpiredApplicants().catch(e => console.error('⚠️  purge failed:', e.message)); });

const PORT = parseInt(process.env.PORT || '3000', 10);

connectMongoWithRetry().then(() => {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 BLS Server on port ${PORT}`);
    console.log('🔀 Sync mode: MERGE by PassportNo (no more overwrites)');
    console.log('🗑️  Atomic deletes: single applicant + group endpoints');
    console.log('🔔 Force sync: POST /api/force-sync to push to all extensions');
    console.log('🔄 Dashboard: auto-refreshes every 10 seconds');
    console.log('📇 Profiles API: /api/profiles (Firebase replacement for the userscript)');
    console.log('📲 Hourly WhatsApp change-notification: active (needs CALLMEBOT_PHONE + CALLMEBOT_APIKEY)');
    console.log(mongoReady ? '🗄️  Persistence: MongoDB (data survives restarts)' : '⚠️  Persistence: IN-MEMORY ONLY (data will be lost on restart — set MONGODB_URI)');
  });
});
