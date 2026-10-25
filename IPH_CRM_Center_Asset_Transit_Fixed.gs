/**
 * IPH CRM INDIVILLAGE — Secure Google Apps Script backend
 * Replace Code.gs with this file, review the deployment instructions, and redeploy.
 *
 * Security notes:
 * - No hard-coded user/password bypass is included.
 * - Existing plain-text Password values are supported for migration only; after a successful
 *   login they are converted to salted PBKDF2-HMAC-SHA256 hashes and the plain-text value is cleared.
 * - All inventory and account-management requests require a server-issued session token.
 * - Google Authenticator TOTP secrets and recovery-code hashes are kept server-side.
 * - Admin/center account credentials are never returned to the browser.
 */
const SHEET_NAME = 'Master_Inventory_Data';
const AUTH_SHEET_NAME = 'Auth_Data';
const SESSION_TTL_SECONDS = 21600; // 6 hours; Apps Script CacheService maximum TTL
const CHALLENGE_TTL_SECONDS = 300; // 5 minutes
const MAX_LOGIN_FAILURES = 8;
const MAX_MFA_ATTEMPTS = 5;
const PASSWORD_HASH_ITERATIONS = 5000; // User-selected faster setting; weaker password-hash resistance than higher iteration counts.
const AUTH_HEADERS = [
  'Username', 'PasswordSalt', 'PasswordHash', 'PasswordIterations', 'Password', 'Role', 'CenterName',
  'TOTPSecret', 'TOTPEnabled', 'RecoveryHashes'
];

function doPost(e) {
  let action = 'unknown';
  const requestId = Utilities.getUuid();
  try {
    if (!e || !e.postData || !e.postData.contents) return json({ status: 'error', message: 'Missing request body.' });
    const payload = JSON.parse(e.postData.contents);
    action = String(payload.action || '');
    switch (action) {
      case 'login': return handleLogin(payload.username, payload.password);
      case 'verify_login_otp': return handleLoginOtp(payload.challengeId, payload.code);
      case 'validate_session': {
        const session = getSession(payload.token);
        return session ? json({ status: 'success', data: session }) : json({ status: 'error', message: 'Session expired. Please sign in again.' });
      }
      case 'logout': {
        if (payload.token) CacheService.getScriptCache().remove('session:' + payload.token);
        return json({ status: 'success' });
      }
      case 'get_security_status': return handleGetSecurityStatus(payload);
      case 'begin_totp_setup': return handleBeginTotpSetup(payload);
      case 'confirm_totp_setup': return handleConfirmTotpSetup(payload);
      case 'disable_totp': return handleDisableTotp(payload);
      case 'read': return handleReadInventory(payload);
      case 'write': return handleWriteInventory(payload);
      case 'transit_asset': return handleTransitAsset(payload);
      case 'read_centers': return handleReadCenters(payload);
      case 'save_centers': return handleSaveCenters(payload);
      default: return json({ status: 'error', message: 'Invalid action.' });
    }
  } catch (err) {
    // Diagnostic logging: action, request ID, and stack only. Never log passwords,
    // TOTP secrets, recovery codes, or submitted verification codes.
    const safeMessage = err && err.message ? String(err.message) : String(err);
    console.error('CRM request failure [' + requestId + '] action=' + action +
      ' message=' + safeMessage + '\n' + (err && err.stack ? err.stack : 'No stack available'));
    return json({
      status: 'error',
      message: 'Server error during ' + (action || 'request') + '. Reference: ' + requestId
    });
  }
}

function doGet() {
  return json({ status: 'error', message: 'Please send a POST request with a JSON body.' });
}

function handleLogin(username, password) {
  username = String(username || '').trim();
  password = String(password || '');
  if (!username || !password) return json({ status: 'error', message: 'Enter username and password.' });
  const cache = CacheService.getScriptCache();
  const failKey = 'login_fail:' + sha256Text(username.toLowerCase()).substring(0, 32);
  const failures = Number(cache.get(failKey) || 0);
  if (failures >= MAX_LOGIN_FAILURES) return json({ status: 'error', message: 'Too many login attempts. Wait 15 minutes and try again.' });

  const records = getAuthRecords();
  const user = findUser(records, username);
  if (!user || !verifyPasswordAndUpgrade(user, password, records)) {
    cache.put(failKey, String(failures + 1), 900);
    return json({ status: 'error', message: 'Invalid username or password.' });
  }
  cache.remove(failKey);

  if (truthy(user.TOTPEnabled)) {
    if (!getTotpSecret(user.Username)) {
      return json({ status: 'error', message: 'Authenticator configuration is missing. Contact the system administrator for recovery.' });
    }
    const challengeId = randomToken();
    cache.put('challenge:' + challengeId, JSON.stringify({ username: user.Username, attempts: 0 }), CHALLENGE_TTL_SECONDS);
    return json({ status: 'mfa_required', challengeId: challengeId, message: 'Enter the current code from your authenticator app.' });
  }
  return json({ status: 'success', data: issueSession(user) });
}

function handleLoginOtp(challengeId, code) {
  const cache = CacheService.getScriptCache();
  const key = 'challenge:' + String(challengeId || '');
  const raw = cache.get(key);
  if (!raw) return json({ status: 'error', message: 'Verification expired. Sign in again.' });
  const challenge = JSON.parse(raw);
  if (challenge.attempts >= MAX_MFA_ATTEMPTS) {
    cache.remove(key);
    return json({ status: 'error', message: 'Too many verification attempts. Sign in again.' });
  }
  const records = getAuthRecords();
  const user = findUser(records, challenge.username);
  const totpSecret = user ? getTotpSecret(user.Username) : '';
  if (!user || !truthy(user.TOTPEnabled) || !totpSecret) {
    cache.remove(key);
    return json({ status: 'error', message: 'Authenticator enrollment changed. Sign in again.' });
  }
  let valid = verifyTotp(totpSecret, code);
  if (!valid) valid = consumeRecoveryCode(user, code, records);
  if (!valid) {
    challenge.attempts++;
    if (challenge.attempts >= MAX_MFA_ATTEMPTS) cache.remove(key);
    else cache.put(key, JSON.stringify(challenge), CHALLENGE_TTL_SECONDS);
    return json({ status: 'error', message: 'Invalid code. Check your device time and try again.' });
  }
  cache.remove(key);
  return json({ status: 'success', data: issueSession(user) });
}

function issueSession(user) {
  const token = randomToken() + randomToken();
  const role = normalizeRole(user.Role);
  const session = {
    token: token,
    username: String(user.Username || ''),
    code: (role === 'admin' || role === 'superadmin') ? 'ALL' : String(user.Username || '').toUpperCase(),
    name: String(user.CenterName || user.Username || ''),
    role: role,
    authVersion: String(user.PasswordHash || '')
  };
  CacheService.getScriptCache().put('session:' + token, JSON.stringify(session), SESSION_TTL_SECONDS);
  return session;
}

function getSession(token) {
  if (!token || typeof token !== 'string') return null;
  const cache = CacheService.getScriptCache();
  const cacheKey = 'session:' + token;
  const raw = cache.get(cacheKey);
  if (!raw) return null;
  try {
    const session = JSON.parse(raw);
    const record = findUser(getAuthRecords(), session.username);
    if (!record || normalizeRole(record.Role) !== session.role || String(record.PasswordHash || '') !== String(session.authVersion || '')) {
      cache.remove(cacheKey);
      return null;
    }
    return session;
  } catch (_) {
    cache.remove(cacheKey);
    return null;
  }
}

function requireSession(payload, allowedRoles) {
  const session = getSession(payload && payload.token);
  if (!session) return { error: json({ status: 'error', message: 'Not authenticated or session expired.' }) };
  if (allowedRoles && allowedRoles.indexOf(session.role) === -1) {
    return { error: json({ status: 'error', message: 'Permission denied.' }) };
  }
  return { session: session };
}

function handleGetSecurityStatus(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  const user = findUser(getAuthRecords(), auth.session.username);
  if (!user) return json({ status: 'error', message: 'Account not found.' });
  return json({ status: 'success', data: { totpEnabled: truthy(user.TOTPEnabled), recoveryCodesRemaining: parseRecoveryHashes(user.RecoveryHashes).length } });
}

function totpPropertyKey(username) {
  return 'IPHCRM_TOTP_SECRET_' + usernameKey(username);
}

function getTotpSecret(username) {
  return PropertiesService.getScriptProperties().getProperty(totpPropertyKey(username)) || '';
}

function setTotpSecret(username, secret) {
  const props = PropertiesService.getScriptProperties();
  const key = totpPropertyKey(username);
  if (secret) props.setProperty(key, String(secret));
  else props.deleteProperty(key);
}

function handleBeginTotpSetup(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  const records = getAuthRecords();
  const user = findUser(records, auth.session.username);
  if (!user) return json({ status: 'error', message: 'Account not found.' });
  if (truthy(user.TOTPEnabled)) return json({ status: 'error', message: 'Authenticator is already enabled. Disable it first if you need to re-enroll.' });
  const secret = generateBase32Secret();
  CacheService.getScriptCache().put('totp_pending:' + usernameKey(user.Username), secret, CHALLENGE_TTL_SECONDS);
  const issuer = 'IPH CRM INDIVILLAGE';
  const label = issuer + ':' + String(user.Username);
  const uri = 'otpauth://totp/' + encodeURIComponent(label) + '?secret=' + secret + '&issuer=' + encodeURIComponent(issuer) + '&algorithm=SHA1&digits=6&period=30';
  return json({ status: 'success', data: { secret: secret, otpauthUrl: uri, expiresInSeconds: CHALLENGE_TTL_SECONDS } });
}

function handleConfirmTotpSetup(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;

  // Prevent two confirmation requests from racing on the same account/sheet.
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) {
    return json({ status: 'error', message: 'The security settings are busy. Wait a few seconds and try again.' });
  }

  const username = String(auth.session.username || '').trim();
  const pendingKey = 'totp_pending:' + usernameKey(username);
  try {
    const cache = CacheService.getScriptCache();
    const secret = cache.get(pendingKey);
    if (!secret) return json({ status: 'error', message: 'Setup expired. Generate a new QR code.' });
    if (!verifyTotp(secret, payload.code)) {
      return json({ status: 'error', message: 'Incorrect code. Scan the QR code and enter the current six-digit code.' });
    }

    const records = getAuthRecords();
    const user = findUser(records, username);
    if (!user) return json({ status: 'error', message: 'Account not found.' });
    if (truthy(user.TOTPEnabled)) {
      cache.remove(pendingKey);
      return json({ status: 'error', message: 'Authenticator is already enabled for this account.' });
    }

    const recoveryCodes = generateRecoveryCodes(8);
    const oldSecret = getTotpSecret(user.Username);
    user.TOTPSecret = ''; // Never store the TOTP seed in the spreadsheet.
    user.TOTPEnabled = 'TRUE';
    user.RecoveryHashes = JSON.stringify(recoveryCodes.map(sha256Text));

    // Store the secret first, then persist the account flags. Roll back the secret if sheet write fails.
    setTotpSecret(user.Username, secret);
    try {
      updateAuthSecurityFields(user.Username, 'TRUE', user.RecoveryHashes);
    } catch (sheetError) {
      if (oldSecret) setTotpSecret(user.Username, oldSecret);
      else setTotpSecret(user.Username, '');
      throw sheetError;
    }

    cache.remove(pendingKey);
    return json({ status: 'success', data: { totpEnabled: true, recoveryCodes: recoveryCodes } });
  } catch (err) {
    // Log only an account key and exception; never log the secret, code, or recovery codes.
    const requestId = Utilities.getUuid();
    const safeMessage = err && err.message ? String(err.message) : String(err);
    console.error('confirm_totp_setup failure [' + requestId + '] account=' + usernameKey(username) +
      ' message=' + safeMessage + '\n' + (err && err.stack ? err.stack : 'No stack available'));
    // Return a safe diagnostic message so troubleshooting does not depend solely on delayed Cloud logs.
    // Do not include TOTP secrets, submitted codes, or recovery codes in this response.
    return json({ status: 'error', message: 'Could not enable Authenticator: ' + safeMessage + '. Reference: ' + requestId });
  } finally {
    lock.releaseLock();
  }
}


/** Update only the target account's security columns; avoid rewriting the entire Auth_Data sheet. */
function updateAuthSecurityFields(username, enabled, recoveryHashes) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) throw new Error('No active spreadsheet. Ensure this Apps Script is bound to the CRM Google Sheet.');

  const sheet = ss.getSheetByName(AUTH_SHEET_NAME);
  if (!sheet) throw new Error('Auth_Data sheet was not found. Create a sheet named Auth_Data.');
  if (sheet.getLastRow() < 2) throw new Error('Auth_Data has no account rows.');

  // Ensure the required columns exist before looking up their indexes.
  const requiredHeaders = ['Username', 'TOTPSecret', 'TOTPEnabled', 'RecoveryHashes'];
  const lastCol = Math.max(sheet.getLastColumn(), 1);
  let headers = sheet.getRange(1, 1, 1, lastCol).getDisplayValues()[0].map(h => String(h || '').trim());
  let changed = false;
  requiredHeaders.forEach(function(header) {
    if (headers.indexOf(header) === -1) {
      headers.push(header);
      changed = true;
    }
  });
  if (changed) {
    sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    SpreadsheetApp.flush();
  }

  const usernameCol = headers.indexOf('Username') + 1;
  const enabledCol = headers.indexOf('TOTPEnabled') + 1;
  const recoveryCol = headers.indexOf('RecoveryHashes') + 1;
  const secretCol = headers.indexOf('TOTPSecret') + 1;
  if (!usernameCol || !enabledCol || !recoveryCol || !secretCol) {
    throw new Error('Could not prepare required Auth_Data security columns. Check the first row headers.');
  }

  const rowCount = sheet.getLastRow() - 1;
  const usernames = sheet.getRange(2, usernameCol, rowCount, 1).getDisplayValues();
  const wanted = String(username || '').trim().toLowerCase();
  let rowNumber = -1;
  for (let i = 0; i < usernames.length; i++) {
    if (String(usernames[i][0] || '').trim().toLowerCase() === wanted) {
      rowNumber = i + 2;
      break;
    }
  }
  if (rowNumber < 0) throw new Error('Account row not found in Auth_Data for the signed-in user. Check the Username column.');

  // Store the TOTP seed only in Script Properties, never in the spreadsheet.
  sheet.getRange(rowNumber, secretCol).setValue('');
  sheet.getRange(rowNumber, enabledCol).setValue(enabled);
  sheet.getRange(rowNumber, recoveryCol).setValue(recoveryHashes || '[]');
  SpreadsheetApp.flush();
}

function handleDisableTotp(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  const records = getAuthRecords();
  const user = findUser(records, auth.session.username);
  if (!user || !truthy(user.TOTPEnabled)) return json({ status: 'error', message: 'Authenticator is not enabled.' });
  const currentSecret = getTotpSecret(user.Username);
  if (!currentSecret || !verifyTotp(currentSecret, payload.code)) return json({ status: 'error', message: 'The current authenticator code is incorrect.' });
  setTotpSecret(user.Username, '');
  try {
    updateAuthSecurityFields(user.Username, 'FALSE', '[]');
  } catch (err) {
    setTotpSecret(user.Username, currentSecret);
    throw err;
  }
  return json({ status: 'success', message: 'Authenticator disabled.' });
}

function handleReadInventory(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  let data = readData(SHEET_NAME);
  // Center accounts receive only their own assets and records involved in transfers to/from them.
  if (auth.session.role === 'center') {
    const code = String(auth.session.code || '').toLowerCase();
    data = data.filter(row => {
      const loc = valueFrom(row, ['Location', 'location', 'Center', 'center']).toLowerCase();
      const from = valueFrom(row, ['Transit From', 'transitFrom']).toLowerCase();
      const to = valueFrom(row, ['Transit To', 'transitTo']).toLowerCase();
      return loc === code || from === code || to === code;
    });
  }
  return json({ status: 'success', data: data });
}

function handleWriteInventory(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  if (!Array.isArray(payload.data)) return json({ status: 'error', message: 'Inventory data must be an array.' });
  const role = String(auth.session.role || '').toLowerCase();
  if (role === 'admin' || role === 'superadmin') {
    // Preserve existing privileged bulk-sync behavior for Admin/Super Admin.
    writeData(SHEET_NAME, payload.data);
    CacheService.getScriptCache().remove('inventory_cache');
    return json({ status: 'success', message: 'Inventory synced.' });
  }
  if (role !== 'center') return json({ status: 'error', message: 'You do not have permission to edit inventory.' });
  return writeCenterInventoryRows_(auth.session, payload.data);
}

/**
 * Center-scoped inventory writer. Centers can add/edit only assets assigned to
 * their own center. This performs row-level updates/appends and never clears or
 * rewrites the entire inventory sheet. Transfer fields remain controlled by
 * handleTransitAsset, not by this general inventory endpoint.
 */
function writeCenterInventoryRows_(session, incoming) {
  const ownCode = String(session.code || session.username || '').trim();
  if (!ownCode) return json({ status: 'error', message: 'Your center code is missing from the session.' });
  const equals = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return json({ status: 'error', message: 'Inventory is busy. Please try again.' });
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) throw new Error('No active spreadsheet is available.');
    const sheet = ss.getSheetByName(SHEET_NAME);
    if (!sheet) throw new Error('Inventory sheet ' + SHEET_NAME + ' was not found.');
    const lastRow = sheet.getLastRow();
    const lastCol = sheet.getLastColumn();
    if (lastRow < 1 || lastCol < 1) return json({ status: 'error', message: 'Inventory sheet has no header row.' });
    const headers = sheet.getRange(1, 1, 1, lastCol).getDisplayValues()[0].map(h => String(h || '').trim());
    const col = name => headers.findIndex(h => h.toLowerCase() === name.toLowerCase());
    const locationCol = col('Location');
    const tagCol = col('Tag ID');
    const imeiCol = col('IMEI 1') >= 0 ? col('IMEI 1') : col('IMEI');
    if (locationCol < 0) return json({ status: 'error', message: 'Inventory sheet needs a Location column.' });
    if (tagCol < 0 && imeiCol < 0) return json({ status: 'error', message: 'Inventory sheet needs Tag ID or IMEI column.' });

    const allRows = lastRow > 1 ? sheet.getRange(2, 1, lastRow - 1, lastCol).getValues() : [];
    const keyFor = (tag, imei) => (String(tag || '').trim().toLowerCase() ? 'tag:' + String(tag).trim().toLowerCase() : '') || (String(imei || '').trim().toLowerCase() ? 'imei:' + String(imei).trim().toLowerCase() : '');
    const rowIndexByKey = new Map();
    allRows.forEach((row, i) => {
      const key = keyFor(tagCol >= 0 ? row[tagCol] : '', imeiCol >= 0 ? row[imeiCol] : '');
      if (key && !rowIndexByKey.has(key)) rowIndexByKey.set(key, i + 2);
    });
    const blockedHeaders = new Set(['Transit Status','Transit From','Transit To','Transit Date','Transit Previous Status','Received Date','Transit Remarks']);
    const allowedHeaders = new Set(['S No','Tag ID','Location','Project Name','Model Name','Supplier','IMEI 1','IMEI','Storage','Mobile Color','Color','Device Status','Status','Asset Date','Date of Asset Added','Last Edited By','Last Edited Time']);
    let updated = 0, added = 0;
    for (let n = 0; n < incoming.length; n++) {
      const obj = incoming[n] || {};
      const rowLocation = String(obj['Location'] ?? obj.location ?? ownCode).trim();
      if (!equals(rowLocation, ownCode)) {
        return json({ status: 'error', message: 'Center users can only add or edit assets assigned to their own center (' + ownCode + ').' });
      }
      const tag = obj['Tag ID'] ?? obj.tagId ?? '';
      const imei = obj['IMEI 1'] ?? obj.IMEI ?? obj.imei ?? '';
      const key = keyFor(tag, imei);
      if (!key) return json({ status: 'error', message: 'Every asset must have a Tag ID or IMEI.' });
      const rowNum = rowIndexByKey.get(key);
      let row;
      if (rowNum) {
        row = sheet.getRange(rowNum, 1, 1, lastCol).getValues()[0];
        if (!equals(row[locationCol], ownCode)) {
          return json({ status: 'error', message: 'You cannot edit an asset that is not currently assigned to your center.' });
        }
      } else {
        row = new Array(lastCol).fill('');
        row[locationCol] = ownCode;
      }
      Object.keys(obj).forEach(k => {
        const header = headers.find(h => h.toLowerCase() === String(k).toLowerCase());
        if (!header || blockedHeaders.has(header) || !allowedHeaders.has(header)) return;
        const ci = col(header);
        if (ci < 0) return;
        if (header.toLowerCase() === 'location') row[ci] = ownCode;
        else row[ci] = obj[k] == null ? '' : obj[k];
      });
      // Keep the location pinned to the authenticated center even if the client is modified.
      row[locationCol] = ownCode;
      const editorCol = col('Last Edited By');
      const timeCol = col('Last Edited Time');
      if (editorCol >= 0) row[editorCol] = String(session.name || session.username || 'Center User') + ' (' + ownCode + ')';
      if (timeCol >= 0) row[timeCol] = transitNow_();
      if (rowNum) {
        sheet.getRange(rowNum, 1, 1, lastCol).setValues([row]);
        updated++;
      } else {
        sheet.appendRow(row);
        added++;
        const insertedRow = sheet.getLastRow();
        rowIndexByKey.set(key, insertedRow);
      }
    }
    SpreadsheetApp.flush();
    CacheService.getScriptCache().remove('inventory_cache');
    return json({ status: 'success', message: 'Center inventory synced.', updated: updated, added: added });
  } catch (err) {
    const message = err && err.message ? String(err.message) : String(err);
    console.error('center inventory write failed: ' + message + '\n' + (err && err.stack ? err.stack : 'No stack available'));
    return json({ status: 'error', message: 'Center inventory save failed: ' + message });
  } finally {
    lock.releaseLock();
  }
}


/**
 * Secure, row-level asset transfer endpoint for Center, Admin and Super Admin.
 * Centers may transfer only assets assigned to their own center, receive only
 * assets addressed to their center, and cancel only transfers they originated.
 * This avoids granting center accounts access to the whole-sheet write endpoint.
 */
function handleTransitAsset(payload) {
  const auth = requireSession(payload);
  if (auth.error) return auth.error;
  const session = auth.session;
  const isAdmin = ['admin', 'superadmin'].includes(session.role);
  const tagId = String(payload.tagId || '').trim();
  const imei = String(payload.imei || '').trim();
  const status = String(payload.transitStatus || '').trim();
  const from = String(payload.from || '').trim();
  const to = String(payload.to || '').trim();
  const note = String(payload.note || '').trim().slice(0, 500);
  if ((!tagId && !imei) || !['In Transit', 'Received', 'Cancelled'].includes(status)) {
    return json({ status: 'error', message: 'Asset identifier or transfer status is missing/invalid.' });
  }
  if (status === 'In Transit' && (!from || !to || from.toLowerCase() === to.toLowerCase())) {
    return json({ status: 'error', message: 'Choose different source and destination centers.' });
  }
  const lock = LockService.getScriptLock();
  if (!lock.tryLock(10000)) return json({ status: 'error', message: 'Asset records are busy. Try again shortly.' });
  try {
    const ss = SpreadsheetApp.getActiveSpreadsheet();
    if (!ss) throw new Error('No active spreadsheet. Ensure this Apps Script project is bound to the CRM Google Sheet.');
    const sheet = ss.getSheetByName(SHEET_NAME);
    if (!sheet) throw new Error('Inventory sheet ' + SHEET_NAME + ' was not found. Check the sheet tab name.');
    if (sheet.getLastRow() < 2) return json({ status: 'error', message: 'Inventory sheet has no asset rows.' });
    const requiredTransitHeaders = ['Transit Status', 'Transit From', 'Transit To', 'Transit Date', 'Transit Previous Status', 'Received Date', 'Transit Remarks', 'Last Edited By', 'Last Edited Time'];
    let headers = sheet.getRange(1, 1, 1, Math.max(sheet.getLastColumn(), 1)).getDisplayValues()[0].map(h => String(h || '').trim());
    let headersChanged = false;
    requiredTransitHeaders.forEach(h => { if (headers.indexOf(h) < 0) { headers.push(h); headersChanged = true; } });
    if (headersChanged) sheet.getRange(1, 1, 1, headers.length).setValues([headers]);
    const values = sheet.getRange(1, 1, sheet.getLastRow(), headers.length).getValues();
    headers = values[0].map(h => String(h || '').trim());
    const col = name => headers.indexOf(name);
    const tagCol = col('Tag ID');
    const imeiCol = col('IMEI 1') >= 0 ? col('IMEI 1') : col('IMEI');
    const locCol = col('Location');
    const statusHeader = col('Device Status') >= 0 ? 'Device Status' : 'Status';
    const statusCol = col(statusHeader);
    if (locCol < 0 || statusCol < 0) return json({ status: 'error', message: 'Inventory sheet needs Location and Device Status columns.' });
    const matches = [];
    for (let i = 1; i < values.length; i++) {
      const rowTag = tagCol >= 0 ? String(values[i][tagCol] || '').trim() : '';
      const rowImei = imeiCol >= 0 ? String(values[i][imeiCol] || '').trim() : '';
      const tagMatch = tagId && rowTag.toLowerCase() === tagId.toLowerCase();
      const imeiMatch = imei && rowImei.toLowerCase() === imei.toLowerCase();
      if ((tagId && imei) ? (tagMatch && imeiMatch) : (tagMatch || imeiMatch)) matches.push(i + 1);
    }
    if (matches.length !== 1) return json({ status: 'error', message: matches.length ? 'Asset identifier is not unique. Contact Admin.' : 'Asset not found. Refresh inventory and try again.' });
    const rowNumber = matches[0];
    const row = values[rowNumber - 1];
    const read = name => { const i = col(name); return i >= 0 ? String(row[i] || '').trim() : ''; };
    const write = (name, value) => { const i = col(name); if (i >= 0) sheet.getRange(rowNumber, i + 1).setValue(value); };
    const location = String(row[locCol] || '').trim();
    const currentTransit = read('Transit Status');
    const currentFrom = read('Transit From');
    const currentTo = read('Transit To');
    const previousStatus = read('Transit Previous Status') || (read('Device Status') || read('Status') || 'Active');
    const ownCode = String(session.code || session.username || '').trim();
    const equals = (a, b) => String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
    if (status === 'In Transit') {
      if (!isAdmin && (!equals(from, ownCode) || !equals(location, ownCode))) return json({ status: 'error', message: 'You can only transfer assets currently assigned to your center.' });
      if (currentTransit === 'In Transit') return json({ status: 'error', message: 'This asset already has a pending transfer.' });
      if (!isAdmin && !equals(from, ownCode)) return json({ status: 'error', message: 'Only the source center can start this transfer.' });
      write('Transit Previous Status', read('Device Status') || read('Status') || 'Active');
      write('Transit From', from); write('Transit To', to); write('Transit Status', 'In Transit');
      write('Transit Date', transitNow_()); write('Received Date', ''); write('Transit Remarks', note);
      // Do not overwrite the device-status field with 'In Transit'.
      // Transit state belongs only in the dedicated Transit Status column.
    } else if (status === 'Received') {
      if (currentTransit !== 'In Transit') return json({ status: 'error', message: 'There is no pending transfer for this asset.' });
      if (!isAdmin && !equals(currentTo, ownCode)) return json({ status: 'error', message: 'Only the destination center can confirm receipt.' });
      // Keep the device-status cell untouched: its dropdown may allow only
      // specific repair statuses. Transfer state is tracked in Transit Status.
      write('Location', currentTo);
      write('Transit Status', 'Received'); write('Received Date', transitNow_());
      if (note) write('Transit Remarks', note);
    } else {
      if (currentTransit !== 'In Transit') return json({ status: 'error', message: 'There is no pending transfer to cancel.' });
      if (!isAdmin && !equals(currentFrom, ownCode)) return json({ status: 'error', message: 'Only the source center or Admin can cancel this transfer.' });
      // Keep the device-status cell untouched on cancellation as well.
      write('Location', currentFrom);
      write('Transit Status', 'Cancelled'); write('Received Date', '');
      if (note) write('Transit Remarks', note);
    }
    write('Last Edited By', String(session.name || session.username || 'User') + ' (' + ownCode + ')');
    write('Last Edited Time', transitNow_());
    SpreadsheetApp.flush();
    CacheService.getScriptCache().remove('inventory_cache');
    return json({ status: 'success', message: 'Transfer updated successfully.' });
  } catch (err) {
    const message = err && err.message ? String(err.message) : String(err);
    console.error('transit_asset failed: ' + message + '\n' + (err && err.stack ? err.stack : 'No stack available'));
    return json({ status: 'error', message: 'Asset transfer failed: ' + message });
  } finally {
    lock.releaseLock();
  }
}

function transitNow_() {
  return Utilities.formatDate(new Date(), Session.getScriptTimeZone() || 'Asia/Kolkata', 'dd MMM yyyy, hh:mm a');
}

function handleReadCenters(payload) {
  const auth = requireSession(payload, ['admin', 'superadmin']);
  if (auth.error) return auth.error;
  const records = getAuthRecords()
    .filter(u => normalizeRole(u.Role) === 'center')
    .map(u => ({ Username: String(u.Username || ''), CenterName: String(u.CenterName || ''), Role: 'center' }));
  return json({ status: 'success', data: records });
}

function handleSaveCenters(payload) {
  const auth = requireSession(payload, ['admin', 'superadmin']);
  if (auth.error) return auth.error;
  if (!Array.isArray(payload.data)) return json({ status: 'error', message: 'Center data must be an array.' });
  const records = getAuthRecords();
  const privileged = records.filter(u => ['admin', 'superadmin'].includes(normalizeRole(u.Role)));
  const existingCenters = records.filter(u => normalizeRole(u.Role) === 'center');
  const incoming = new Map();
  payload.data.forEach(item => {
    const username = String(item.Username || '').trim().toUpperCase();
    if (!username || username.length > 60 || !/^[A-Z0-9._-]+$/.test(username)) return;
    const role = normalizeRole(item.Role || 'center');
    if (role !== 'center') return; // This endpoint can never modify admin/superadmin users.
    incoming.set(username, { username: username, name: String(item.CenterName || '').trim(), password: String(item.Password || '') });
  });

  const savedCenters = [];
  incoming.forEach((item, username) => {
    if (!item.name) return;
    let old = existingCenters.find(u => String(u.Username || '').toUpperCase() === username);
    if (old) {
      old.CenterName = item.name;
      if (item.password) {
        if (item.password.length < 8) throw new Error('New passwords must contain at least 8 characters.');
        setPasswordHash(old, item.password);
      }
      old.Role = 'center';
      savedCenters.push(old);
    } else if (item.password) {
      if (item.password.length < 8) throw new Error('New center passwords must contain at least 8 characters.');
      const fresh = { Username: username, Role: 'center', CenterName: item.name, TOTPSecret: '', TOTPEnabled: 'FALSE', RecoveryHashes: '[]' };
      setPasswordHash(fresh, item.password);
      savedCenters.push(fresh);
    }
    // Unconfigured placeholder rows intentionally do not create login accounts.
  });
  const retainedNames = new Set(savedCenters.map(u => String(u.Username || '').toLowerCase()));
  existingCenters.forEach(u => { if (!retainedNames.has(String(u.Username || '').toLowerCase())) setTotpSecret(u.Username, ''); });
  writeAuthRecords(privileged.concat(savedCenters));
  return json({ status: 'success', message: 'Center accounts saved. Unconfigured placeholders were not given login access.' });
}

function verifyPasswordAndUpgrade(user, password, allRecords) {
  let valid = false;
  let shouldSave = false;

  if (String(user.PasswordHash || '') && String(user.PasswordSalt || '')) {
    // Existing hashes without PasswordIterations were created with the legacy 60,000 iterations.
    const storedIterations = Number(user.PasswordIterations) || 60000;
    valid = hashPassword(password, String(user.PasswordSalt), storedIterations) === String(user.PasswordHash);

    // Rehash successful legacy logins at the current Apps Script-friendly cost.
    if (valid && storedIterations !== PASSWORD_HASH_ITERATIONS) {
      setPasswordHash(user, password);
      shouldSave = true;
    }
  } else if (String(user.Password || '') !== '') {
    valid = String(user.Password) === password;
    if (valid) {
      setPasswordHash(user, password);
      shouldSave = true;
    }
  }

  if (!valid) return false;
  // Update only this account's security cells. Rewriting the entire Auth_Data sheet
  // on login is slow and can overwrite concurrent changes made by another admin.
  if (shouldSave) writeAuthUserFields(user, ['PasswordSalt', 'PasswordHash', 'PasswordIterations', 'Password']);
  return true;
}

/** Write only specified fields for one user; never clear/rewrite the whole Auth_Data sheet. */
function writeAuthUserFields(user, fields) {
  const cache = CacheService.getScriptCache();
  cache.remove('auth_records_v1');
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getSheetByName(AUTH_SHEET_NAME);
  if (!sheet || sheet.getLastRow() < 2) throw new Error('Auth_Data account row was not found.');
  const lastCol = sheet.getLastColumn();
  const headers = sheet.getRange(1, 1, 1, lastCol).getDisplayValues()[0].map(v => String(v || '').trim());
  const usernameCol = headers.indexOf('Username') + 1;
  if (!usernameCol) throw new Error('Auth_Data is missing the Username column.');
  const usernames = sheet.getRange(2, usernameCol, sheet.getLastRow() - 1, 1).getDisplayValues();
  const wanted = String(user.Username || '').trim().toLowerCase();
  let rowNumber = 0;
  for (let i = 0; i < usernames.length; i++) {
    if (String(usernames[i][0] || '').trim().toLowerCase() === wanted) { rowNumber = i + 2; break; }
  }
  if (!rowNumber) throw new Error('Auth_Data account row was not found for the user.');
  fields.forEach(field => {
    const col = headers.indexOf(field) + 1;
    if (col > 0) sheet.getRange(rowNumber, col).setValue(user[field] == null ? '' : user[field]);
  });
}

function setPasswordHash(user, password) {
  const salt = randomToken().substring(0, 32);
  user.PasswordSalt = salt;
  user.PasswordIterations = PASSWORD_HASH_ITERATIONS;
  user.PasswordHash = hashPassword(password, salt, PASSWORD_HASH_ITERATIONS);
  user.Password = '';
}

function hashPassword(password, salt, iterations) {
  // PBKDF2-HMAC-SHA256, with per-account iteration count for safe migration.
  // Apps Script Utilities accepts byte arrays for HMAC inputs and keys.
  const rounds = Math.max(1, Math.min(200000, Number(iterations) || PASSWORD_HASH_ITERATIONS));
  const passwordBytes = Utilities.newBlob(String(password)).getBytes();
  const saltBytes = Utilities.newBlob(String(salt)).getBytes().concat([0, 0, 0, 1]);
  let u = Utilities.computeHmacSha256Signature(saltBytes, passwordBytes);
  let derived = u.slice();
  for (let i = 1; i < rounds; i++) {
    u = Utilities.computeHmacSha256Signature(u, passwordBytes);
    for (let j = 0; j < derived.length; j++) derived[j] = derived[j] ^ u[j];
  }
  return Utilities.base64Encode(derived);
}

function getAuthRecords() {
  // Short server-side cache avoids repeated Spreadsheet reads during login,
  // session validation, MFA verification, and normal authenticated API calls.
  // Cache is invalidated whenever auth records are written; external sheet edits
  // may take up to 30 seconds to appear.
  const cache = CacheService.getScriptCache();
  const cacheKey = 'auth_records_v1';
  const cached = cache.get(cacheKey);
  if (cached) {
    try { return JSON.parse(cached); } catch (_) { cache.remove(cacheKey); }
  }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(AUTH_SHEET_NAME);
  if (!sheet) {
    sheet = ss.insertSheet(AUTH_SHEET_NAME);
    sheet.getRange(1, 1, 1, AUTH_HEADERS.length).setValues([AUTH_HEADERS]);
    return [];
  }
  if (sheet.getLastRow() === 0) {
    sheet.getRange(1, 1, 1, AUTH_HEADERS.length).setValues([AUTH_HEADERS]);
    return [];
  }
  const lastCol = Math.max(1, sheet.getLastColumn());
  let headers = sheet.getRange(1, 1, 1, lastCol).getDisplayValues()[0].map(h => String(h || '').trim());
  AUTH_HEADERS.forEach(h => { if (headers.indexOf(h) === -1) headers.push(h); });
  if (headers.length !== lastCol) sheet.getRange(1, 1, 1, headers.length).setValues([headers]);

  const values = sheet.getDataRange().getValues();
  const actualHeaders = values[0].map(h => String(h || '').trim());
  const records = values.slice(1).filter(row => row.some(v => v !== '' && v !== null)).map(row => {
    const item = {};
    actualHeaders.forEach((header, i) => { if (header) item[header] = row[i] == null ? '' : row[i]; });
    return item;
  });

  // Migrate any legacy TOTP seeds with targeted cell updates instead of rewriting
  // the complete sheet. This keeps first login fast and avoids overwriting other edits.
  records.forEach(item => {
    if (String(item.TOTPSecret || '').trim()) {
      if (truthy(item.TOTPEnabled)) setTotpSecret(item.Username, String(item.TOTPSecret));
      item.TOTPSecret = '';
      writeAuthUserFields(item, ['TOTPSecret']);
    }
  });

  // CacheService has a per-value size limit. Skip caching if this sheet is unusually large.
  try {
    const serialized = JSON.stringify(records);
    if (serialized.length < 90000) cache.put(cacheKey, serialized, 30);
  } catch (_) {}
  return records;
}

function writeAuthRecords(records) {
  CacheService.getScriptCache().remove('auth_records_v1');
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(AUTH_SHEET_NAME);
  if (!sheet) sheet = ss.insertSheet(AUTH_SHEET_NAME);
  let headers = [];
  if (sheet.getLastRow() > 0) headers = sheet.getRange(1, 1, 1, Math.max(sheet.getLastColumn(), 1)).getDisplayValues()[0].map(v => String(v || '').trim()).filter(Boolean);
  AUTH_HEADERS.forEach(h => { if (headers.indexOf(h) === -1) headers.push(h); });
  if (!headers.length) headers = AUTH_HEADERS.slice();
  const output = [headers];
  (records || []).forEach(item => output.push(headers.map(h => item[h] !== undefined && item[h] !== null ? item[h] : '')));
  sheet.clearContents();
  sheet.getRange(1, 1, output.length, headers.length).setValues(output);
  sheet.setFrozenRows(1);
}

function findUser(records, username) {
  const wanted = String(username || '').trim().toLowerCase();
  return records.find(u => String(u.Username || '').trim().toLowerCase() === wanted) || null;
}

function readData(sheetName) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = ss.getSheetByName(sheetName);
  if (!sheet || sheet.getLastRow() <= 1 || sheet.getLastColumn() < 1) return [];
  const values = sheet.getDataRange().getValues();
  const headers = values[0].map(h => String(h || '').trim());
  return values.slice(1).filter(row => row.some(v => v !== '' && v !== null)).map(row => {
    const obj = {};
    headers.forEach((header, i) => {
      if (!header) return;
      const cell = row[i];
      obj[header] = cell instanceof Date ? cell.toISOString().split('T')[0] : cell;
    });
    return obj;
  });
}

function writeData(sheetName, dataArray) {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(sheetName);
  if (!sheet) sheet = ss.insertSheet(sheetName);
  if (!Array.isArray(dataArray) || dataArray.length === 0) {
    sheet.clearContents();
    return;
  }
  const headers = Object.keys(dataArray[0]);
  const output = [headers];
  dataArray.forEach(obj => output.push(headers.map(h => obj[h] !== undefined && obj[h] !== null ? obj[h] : '')));
  sheet.clearContents();
  sheet.getRange(1, 1, output.length, headers.length).setValues(output);
  sheet.setFrozenRows(1);
}

function generateBase32Secret() {
  const hex = (Utilities.getUuid() + Utilities.getUuid()).replace(/-/g, '').substring(0, 40);
  const bytes = [];
  for (let i = 0; i < hex.length; i += 2) bytes.push(parseInt(hex.substring(i, i + 2), 16));
  return base32Encode(bytes);
}

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  bytes.forEach(b => {
    value = (value << 8) | (b & 255);
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  });
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(text) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0;
  const output = [];
  String(text || '').toUpperCase().replace(/=+$/g, '').split('').forEach(ch => {
    const index = alphabet.indexOf(ch);
    if (index < 0) return;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  });
  return output.map(b => b > 127 ? b - 256 : b);
}

function verifyTotp(secret, candidate) {
  const code = String(candidate || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(code)) return false;
  const key = base32Decode(secret);
  if (!key.length) return false;
  const counter = Math.floor(Date.now() / 1000 / 30);
  for (let offset = -1; offset <= 1; offset++) {
    const value = counter + offset;
    const msgUnsigned = [0, 0, 0, 0, (value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
    const message = msgUnsigned.map(b => b > 127 ? b - 256 : b);
    const digest = Utilities.computeHmacSignature(Utilities.MacAlgorithm.HMAC_SHA_1, message, key);
    const pos = digest[digest.length - 1] & 15;
    const binary = ((digest[pos] & 127) << 24) | ((digest[pos + 1] & 255) << 16) | ((digest[pos + 2] & 255) << 8) | (digest[pos + 3] & 255);
    const expected = String(binary % 1000000).padStart(6, '0');
    if (expected === code) return true;
  }
  return false;
}

function consumeRecoveryCode(user, code, records) {
  const normalized = String(code || '').trim().toUpperCase();
  if (!normalized) return false;
  const hashes = parseRecoveryHashes(user.RecoveryHashes);
  const target = sha256Text(normalized);
  const index = hashes.indexOf(target);
  if (index < 0) return false;
  hashes.splice(index, 1);
  user.RecoveryHashes = JSON.stringify(hashes);
  writeAuthRecords(records);
  return true;
}

function generateRecoveryCodes(count) {
  const result = [];
  for (let i = 0; i < count; i++) result.push('REC-' + randomToken().substring(0, 16).toUpperCase());
  return result;
}

function parseRecoveryHashes(value) {
  try { const list = JSON.parse(String(value || '[]')); return Array.isArray(list) ? list : []; } catch (_) { return []; }
}

function sha256Text(value) {
  const bytes = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, String(value), Utilities.Charset.UTF_8);
  return Utilities.base64Encode(bytes);
}

function randomToken() {
  return (Utilities.getUuid() + Utilities.getUuid()).replace(/-/g, '');
}

function normalizeRole(role) {
  const normalized = String(role || 'center').trim().toLowerCase().replace(/[ _-]/g, '');
  if (normalized === 'superadmin') return 'superadmin';
  if (normalized === 'admin') return 'admin';
  return 'center';
}

function truthy(value) {
  return value === true || String(value || '').toLowerCase() === 'true' || String(value || '') === '1';
}

function usernameKey(username) {
  return String(username || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '_').substring(0, 80);
}

function valueFrom(obj, keys) {
  for (let i = 0; i < keys.length; i++) if (obj[keys[i]] !== undefined && obj[keys[i]] !== null) return String(obj[keys[i]]).trim();
  return '';
}

function json(object) {
  return ContentService.createTextOutput(JSON.stringify(object)).setMimeType(ContentService.MimeType.JSON);
}