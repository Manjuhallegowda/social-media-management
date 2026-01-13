/**
 * This file contains the Cloudflare Worker logic.
 * In a real deployment, this would be your `src/index.ts` in the Worker project.
 * It handles the API endpoints and the Queue processing.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
// Mock types for Cloudflare environment
interface Env {
  DB: any; // D1Database
  BUCKET: any; // R2Bucket
  QUEUE: any; // Queue
  META_APP_ID: string;
  META_APP_SECRET: string;
  META_REDIRECT_URI: string;
  FRONTEND_URL: string; // URL where this React app is hosted
  API_SECRET: string; // To protect cron/endpoints
  ENCRYPTION_KEY: string; // 32-byte hex string or secret passphrase for AES-GCM
}

// -----------------------------------------------------------------------------
// HELPER: Encryption / Decryption
// -----------------------------------------------------------------------------
async function getCryptoKey(secret: string, salt: Uint8Array): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(secret),
    { name: 'PBKDF2' },
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as any,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptToken(text: string, secret: string): Promise<string> {
  if (!text) return '';
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await getCryptoKey(secret, salt);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);

    const encrypted = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encoded
    );

    // Convert buffer to hex string
    const toHex = (buf: ArrayBuffer) =>
      Array.from(new Uint8Array(buf))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');

    // Format: iv:salt:ciphertext
    return `${toHex(iv.buffer)}:${toHex(salt.buffer)}:${toHex(encrypted)}`;
  } catch (e) {
    console.error('Encryption failed', e);
    throw e;
  }
}

async function decryptToken(
  cipherText: string,
  secret: string
): Promise<string> {
  // Check format. Old format was iv:ciphertext (2 parts). New is iv:salt:ciphertext (3 parts).
  if (!cipherText || !cipherText.includes(':')) return cipherText;

  const parts = cipherText.split(':');
  
  // Backward compatibility: If 2 parts, use the old hardcoded salt logic
  if (parts.length === 2) {
     try {
       const [ivHex, dataHex] = parts;
       // Old hardcoded salt
       const oldSalt = new TextEncoder().encode('social_sync_salt_v1');
       const key = await getCryptoKey(secret, oldSalt);
       
       const fromHex = (hex: string) =>
        new Uint8Array(
          (hex.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
        );

       const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: fromHex(ivHex) },
        key,
        fromHex(dataHex)
      );
      return new TextDecoder().decode(decrypted);
     } catch(e) {
       console.error('Legacy decryption failed', e);
       throw new Error('Failed to decrypt legacy token');
     }
  }

  // New logic for 3 parts
  try {
    const [ivHex, saltHex, dataHex] = parts;
    
    const fromHex = (hex: string) =>
      new Uint8Array(
        (hex.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
      );
      
    const salt = fromHex(saltHex);
    const key = await getCryptoKey(secret, salt);

    const decrypted = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromHex(ivHex) },
      key,
      fromHex(dataHex)
    );

    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error('Decryption failed', e);
    throw new Error('Failed to decrypt token');
  }
}

// -----------------------------------------------------------------------------
// HELPER: Caption Processor (Anti-Spam Logic)
// -----------------------------------------------------------------------------

// Helper to shuffle an array (Fisher-Yates)
function shuffleArray<T>(array: T[]): T[] {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}

function processCaption(base: string, accountName: string): string {
  // 1. Spintax Processing: {Option A|Option B}
  let caption = base.replace(/\{([^{}]+)\}/g, (_match, group) => {
    const options = group.split('|');
    return options[Math.floor(Math.random() * options.length)];
  });

  // 2. Extract and Shuffle Hashtags
  // Regex finds words starting with #.
  const hashtagRegex = /#[\w\u0590-\u05ff]+/g;
  const foundHashtags = caption.match(hashtagRegex) || [];

  // Remove hashtags from the main text to re-append them later in random order
  let cleanCaption = caption.replace(hashtagRegex, '').trim();

  // Shuffle the tags
  const shuffledTags = shuffleArray(foundHashtags).join(' ');

  // 3. Emoji Injection (Add variation to avoid duplicate content detection)
  const emojis = [
    '✨',
    '🚀',
    '🔥',
    '💯',
    '✅',
    '📣',
    '👇',
    '👀',
    '🌟',
    '💫',
    '⚡',
    '📍',
  ];

  // Pick 1-2 random emojis
  const numEmojis = Math.floor(Math.random() * 2) + 1;
  const selectedEmojis = shuffleArray(emojis).slice(0, numEmojis);

  // Inject emojis: Randomly at start, end of text, or replacing double newlines
  const injectionStrategy = Math.random();

  if (injectionStrategy < 0.33) {
    // Prepend
    cleanCaption = `${selectedEmojis.join(' ')} ${cleanCaption}`;
  } else if (injectionStrategy < 0.66) {
    // Append to text body
    cleanCaption = `${cleanCaption} ${selectedEmojis.join(' ')}`;
  } else {
    // If there are paragraphs, insert between them
    cleanCaption = cleanCaption.replace(/\n\n/g, `\n${selectedEmojis[0]}\n`);
  }

  // 4. Final Assembly
  // Add Account Name Variation (invisible separation or explicit) to ensure uniqueness
  // Adding the shuffled hashtags at the end
  let finalPost = cleanCaption;

  // Add hashtags if they existed
  if (shuffledTags.length > 0) {
    finalPost += `\n\n${shuffledTags}`;
  }

  // 10% chance to add location footer for extra uniqueness
  if (Math.random() > 0.9) {
    finalPost += `\n📍 ${accountName}`;
  }

  return finalPost;
}

// -----------------------------------------------------------------------------
// HELPER: JWT Implementation (HS256)
// -----------------------------------------------------------------------------

async function signJwt(payload: any, secret: string): Promise<string> {
  const header = { alg: 'HS256', typ: 'JWT' };
  const encode = (data: any) => 
    btoa(JSON.stringify(data))
      .replace(/=/g, '')
      .replace(/\+/g, '-')
      .replace(/\//g, '_');

  const encodedHeader = encode(header);
  const encodedPayload = encode(payload);

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  );

  const encodedSignature = btoa(
    String.fromCharCode(...new Uint8Array(signature))
  )
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');

  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}

async function verifyJwt(token: string, secret: string): Promise<any> {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid token format');

  const [encodedHeader, encodedPayload, encodedSignature] = parts;

  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const signatureRaw = atob(
    encodedSignature.replace(/-/g, '+').replace(/_/g, '/')
  );
  const signature = new Uint8Array(
    signatureRaw.split('').map((c) => c.charCodeAt(0))
  );

  const isValid = await crypto.subtle.verify(
    'HMAC',
    key,
    signature,
    new TextEncoder().encode(`${encodedHeader}.${encodedPayload}`)
  );

  if (!isValid) throw new Error('Invalid signature');

  const payload = JSON.parse(
    atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'))
  );

  if (payload.exp && Date.now() / 1000 > payload.exp) {
    throw new Error('Token expired');
  }

  return payload;
}

// -----------------------------------------------------------------------------
// HELPER: Password Hashing (bcrypt-like using PBKDF2)
// -----------------------------------------------------------------------------

async function hashPassword(
  password: string,
  secretKey: string
): Promise<string> {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  );

  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256',
    },
    keyMaterial,
    256
  );

  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Convert salt correctly
  const saltHex = Array.from(salt)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  // Return as: iterations:salt:hash
  return `100000:${saltHex}:${hashHex}`;
}

async function verifyPassword(
  password: string,
  storedHash: string,
  secretKey: string
): Promise<boolean> {
  try {
    const parts = storedHash.split(':');
    if (parts.length !== 3) return false;

    const [iterations, saltHex, hashPart] = parts;
    const encoder = new TextEncoder();

    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveBits']
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: Uint8Array.from(
          saltHex.match(/.{1,2}/g)!.map((byte) => parseInt(byte, 16))
        ),
        iterations: parseInt(iterations),
        hash: 'SHA-256',
      },
      keyMaterial,
      256
    );

    const hashArray = Array.from(new Uint8Array(derivedBits));
    const computedHash = hashArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    return computedHash === hashPart;
  } catch (e) {
    console.error('Password verification failed', e);
    return false;
  }
}

// -----------------------------------------------------------------------------
// HELPER: Initialize Admin User (First Run)
// -----------------------------------------------------------------------------

async function ensureAdminUser(env: Env, secretKey: string) {
  try {
    // Ensure admin_users table exists
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS admin_users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at INTEGER,
        last_login INTEGER
      )`
    ).run();
  } catch (e) {
    console.error('Failed to ensure admin user:', e);
  }
}

// -----------------------------------------------------------------------------
// WORKER ENTRY POINT
// -----------------------------------------------------------------------------
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Dynamic CORS Headers
    const origin = request.headers.get('Origin');
    const allowedOrigins = [
      env.FRONTEND_URL, // From wrangler secrets
      'http://localhost:3000',
      'http://localhost:5173', // Vite default
      'https://social-media-management.pages.dev', // Explicitly allow pages dev
    ];

    const corsHeaders: Record<string, string> = {
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS, DELETE, PUT',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (origin && allowedOrigins.includes(origin)) {
      corsHeaders['Access-Control-Allow-Origin'] = origin;
    }

    if (method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // Use ENCRYPTION_KEY if set, otherwise fallback to API_SECRET for dev convenience
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET || 'dev-fallback-secret';
    // Use API_SECRET for JWT signing (ensures it's distinct if keys are rotated)
    const jwtSecret = env.API_SECRET || env.ENCRYPTION_KEY || 'dev-fallback-secret';

    // Ensure admin_users table and default admin exist
    await ensureAdminUser(env, secretKey);

    // Ensure allowed_users table exists (Lazy migration for demo purposes)
    try {
      await env.DB.prepare(
        `
            CREATE TABLE IF NOT EXISTS allowed_users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE,
                created_at INTEGER
            )
        `
      ).run();
    } catch (e) {
      // Ignore if already exists or concurrent creation issues
    }

    // AUTH HELPER
    const authenticate = async () => {
      const authHeader = request.headers.get('Authorization');
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new Error('Unauthorized');
      }
      const token = authHeader.split(' ')[1];
      try {
        const payload = await verifyJwt(token, jwtSecret);
        return payload;
      } catch (e) {
        throw new Error('Unauthorized');
      }
    };

    try {
      // 1. OAUTH: Redirect to Meta
      if (path === '/api/auth/login' && method === 'GET') {
        const source = url.searchParams.get('source') || 'admin';
        // Pass 'source' in the state parameter so we know where to redirect back to
        const state = JSON.stringify({ source });

        const metaUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${
          env.META_APP_ID
        }&redirect_uri=${env.META_REDIRECT_URI}&state=${encodeURIComponent(
          state
        )}&scope=pages_show_list,pages_read_engagement,pages_manage_posts,instagram_basic,instagram_content_publish&response_type=code`;

        // FIXED: Manually construct redirect to include CORS headers
        return new Response(null, {
          status: 302,
          headers: {
            ...corsHeaders,
            Location: metaUrl,
          },
        });
      }

      // 2. OAUTH: Callback (Handle GET redirect from Facebook)
      if (path === '/api/auth/callback' && method === 'GET') {
        const code = url.searchParams.get('code');
        const error = url.searchParams.get('error');
        const stateStr = url.searchParams.get('state');

        let redirectBase = '#accounts'; // Default to connected accounts view

        // Check state to see if this came from the onboarding page
        if (stateStr) {
          try {
            const state = JSON.parse(decodeURIComponent(stateStr));
            if (state.source === 'onboarding') {
              redirectBase = '#onboarding';
            }
          } catch (e) {
            console.warn('Failed to parse state', e);
          }
        }

        // Define fallback frontend URL if env var is missing
        const frontendUrl = env.FRONTEND_URL || 'http://localhost:3000';

        if (error || !code) {
          // FIXED: Manual redirect for CORS
          return new Response(null, {
            status: 302,
            headers: {
              ...corsHeaders,
              Location: `${frontendUrl}/${redirectBase}?error=auth_failed`,
            },
          });
        }

        // Exchange code for token
        const tokenResp = await fetch(
          `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${env.META_APP_ID}&redirect_uri=${env.META_REDIRECT_URI}&client_secret=${env.META_APP_SECRET}&code=${code}`
        );
        const tokenData: any = await tokenResp.json();

        if (!tokenData.access_token) {
          // FIXED: Manual redirect for CORS
          return new Response(null, {
            status: 302,
            headers: {
              ...corsHeaders,
              Location: `${frontendUrl}/${redirectBase}?error=token_failed`,
            },
          });
        }

        // Get Long Lived Token
        const longTokenResp = await fetch(
          `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${env.META_APP_ID}&client_secret=${env.META_APP_SECRET}&fb_exchange_token=${tokenData.access_token}`
        );
        const longTokenData: any = await longTokenResp.json();
        const finalToken = longTokenData.access_token || tokenData.access_token;
        const expiry =
          Date.now() +
          (longTokenData.expires_in
            ? longTokenData.expires_in * 1000
            : 5184000000); // 60 days default

        // Fetch Accounts using the User Token
        // UPDATED: Fetches instagram_business_account{id,username} to store the handle
        const accountsResp = await fetch(
          `https://graph.facebook.com/v19.0/me/accounts?fields=name,access_token,instagram_business_account{id,username}&access_token=${finalToken}`
        );
        const accountsData: any = await accountsResp.json();

        let connectedCount = 0;
        // Fix: Use 'last_updated' instead of 'updated_at' to match SELECT query elsewhere
        const stmt = env.DB.prepare(
          `INSERT OR REPLACE INTO accounts (id, owner_name, fb_page_id, fb_page_name, ig_user_id, ig_username, access_token, token_expires_at, status, created_at, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );

        const batch = [];
        if (accountsData.data) {
          for (const page of accountsData.data) {
            // Only add pages that have a linked Instagram Business Account
            if (page.instagram_business_account) {
              // Crucial: Encrypt and store the PAGE Access Token, not the User Token.
              // This ensures we post AS the Page/Business, not as the User.
              const encryptedPageToken = await encryptToken(
                page.access_token,
                secretKey
              );

              batch.push(
                stmt.bind(
                  crypto.randomUUID(),
                  'Unknown Owner', // In real app, fetch user profile to get real name
                  page.id,
                  page.name,
                  page.instagram_business_account.id,
                  page.instagram_business_account.username || 'unknown', // Store IG Handle
                  encryptedPageToken, // Store Encrypted PAGE Token
                  expiry,
                  'active',
                  Date.now(),
                  Date.now()
                )
              );
              connectedCount++;
            }
          }
        }

        if (batch.length > 0) await env.DB.batch(batch);

        // Redirect back to Frontend with success flag
        // FIXED: Manual redirect for CORS
        return new Response(null, {
          status: 302,
          headers: {
            ...corsHeaders,
            Location: `${frontendUrl}/${redirectBase}?success=true&count=${connectedCount}`,
          },
        });
      }

      // 3. GET ACCOUNTS (Protected)
      if (path === '/api/accounts' && method === 'GET') {
        await authenticate();
        const { results } = await env.DB.prepare(
          'SELECT id, owner_name, fb_page_name, ig_username, status, last_updated FROM accounts ORDER BY created_at DESC'
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // 4. GET DASHBOARD STATS (Protected)
      if (path === '/api/dashboard-stats' && method === 'GET') {
        await authenticate();
        // Aggregate counts
        const totalAccounts = await env.DB.prepare(
          'SELECT count(*) as count FROM accounts'
        ).first('count');
        const activeAccounts = await env.DB.prepare(
          "SELECT count(*) as count FROM accounts WHERE status = 'active'"
        ).first('count');
        const failedTokens = await env.DB.prepare(
          "SELECT count(*) as count FROM accounts WHERE status = 'error'"
        ).first('count');

        // Get recent posts count (last 7 days)
        const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
        const postsCount = await env.DB.prepare(
          'SELECT count(*) as count FROM posts WHERE created_at > ?'
        )
          .bind(oneWeekAgo)
          .first('count');

        return new Response(
          JSON.stringify({
            totalAccounts,
            activeAccounts,
            failedTokens,
            postsCount,
            chartData: [], // TODO: Implement day-by-day aggregation query if D1 allows
          }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // 5. GET POSTS (Protected)
      if (path === '/api/posts' && method === 'GET') {
        await authenticate();
        const { results } = await env.DB.prepare(
          'SELECT * FROM posts ORDER BY created_at DESC'
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // 6. GET LOGS (Protected)
      if (path === '/api/logs' && method === 'GET') {
        await authenticate();
        const postId = url.searchParams.get('postId');
        // FIXED: Add CORS headers to error response
        if (!postId)
          return new Response('Missing postId', {
            status: 400,
            headers: corsHeaders,
          });

        // Join with accounts to get names
        const { results } = await env.DB.prepare(
          `
              SELECT l.*, a.fb_page_name as account_name 
              FROM logs l 
              LEFT JOIN accounts a ON l.account_id = a.id 
              WHERE l.post_id = ? 
              ORDER BY l.timestamp DESC
          `
        )
          .bind(postId)
          .all();

        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // 7. UPLOAD IMAGE (Protected)
      if (path === '/api/upload' && method === 'POST') {
        await authenticate();
        try {
          const formData = await request.formData();
          const file = formData.get('file');

          if (!file || !(file instanceof File)) {
            // FIXED: Add CORS headers to error response
            return new Response('No valid file uploaded', {
              status: 400,
              headers: corsHeaders,
            });
          }

          const key = `uploads/${crypto.randomUUID()}-${file.name.replace(
            /[^a-zA-Z0-9.-]/g,
            ''
          )}`;

          await env.BUCKET.put(key, file.stream(), {
            httpMetadata: { contentType: file.type },
          });

          // Construct Public URL (Assuming Worker serves it at /images/)
          const publicUrl = `${url.origin}/images/${key}`;

          return new Response(JSON.stringify({ url: publicUrl }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        } catch (e: any) {
          console.error('Upload failed', e);
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: corsHeaders,
          });
        }
      }

      // 8. SERVE IMAGES (R2 Proxy)
      if (path.startsWith('/images/') && method === 'GET') {
        // Publicly accessible for now (so FB/IG can download them), but we could sign URLs in future
        const key = path.replace('/images/', '');
        const object = await env.BUCKET.get(key);

        // FIXED: Add CORS headers to error response
        if (!object)
          return new Response('Not Found', {
            status: 404,
            headers: corsHeaders,
          });

        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set('etag', object.httpEtag);
        // Add CORS to image serving as well just in case of canvas usage
        headers.set(
          'Access-Control-Allow-Origin',
          corsHeaders['Access-Control-Allow-Origin'] || '*'
        );

        return new Response(object.body, { headers });
      }

      // 9. CREATE POST (Protected)
      if (path === '/api/posts' && method === 'POST') {
        await authenticate();
        const body = (await request.json()) as any;
        const postId = crypto.randomUUID();

        await env.DB.prepare(
          'INSERT INTO posts (id, public_image_url, base_caption, status, created_at, success_count, failure_count, total_accounts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
        )
          .bind(
            postId,
            body.imageUrl,
            body.caption,
            'pending',
            Date.now(),
            0,
            0,
            0
          )
          .run();

        // Trigger Queue
        await env.QUEUE.send({ type: 'START_POST', postId });

        return new Response(JSON.stringify({ success: true, postId }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // -----------------------------------------------------------------------
      // ALLOWLIST / ACCESS CONTROL ENDPOINTS
      // -----------------------------------------------------------------------

      // Verify User (Client Side) - PUBLIC (Used by onboarding page)
      if (path === '/api/verify-user' && method === 'POST') {
        const { username } = (await request.json()) as any;
        // FIXED: Add CORS headers to error response
        if (!username)
          return new Response('Missing username', {
            status: 400,
            headers: corsHeaders,
          });

        // Case insensitive check
        const user = await env.DB.prepare(
          'SELECT * FROM allowed_users WHERE lower(username) = lower(?)'
        )
          .bind(username)
          .first();

        if (user) {
          return new Response(
            JSON.stringify({ verified: true, username: user.username }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } else {
          return new Response(JSON.stringify({ verified: false }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }

      // Get Allowed Users (Admin) - Protected
      if (path === '/api/allowed-users' && method === 'GET') {
        await authenticate();
        const { results } = await env.DB.prepare(
          'SELECT * FROM allowed_users ORDER BY created_at DESC'
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Add Single Allowed User (Admin) - Protected
      if (path === '/api/allowed-users' && method === 'POST') {
        await authenticate();
        const { username } = (await request.json()) as any;
        // FIXED: Add CORS headers to error response
        if (!username)
          return new Response('Missing username', {
            status: 400,
            headers: corsHeaders,
          });

        try {
          await env.DB.prepare(
            'INSERT INTO allowed_users (id, username, created_at) VALUES (?, ?, ?)'
          )
            .bind(crypto.randomUUID(), username.trim(), Date.now())
            .run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        } catch (e: any) {
          // Likely unique constraint violation
          return new Response(
            JSON.stringify({
              success: false,
              error: 'User likely already exists',
            }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        }
      }

      // Delete Allowed User (Admin) - Protected
      if (path === '/api/allowed-users' && method === 'DELETE') {
        await authenticate();
        const urlParams = new URL(request.url).searchParams;
        const id = urlParams.get('id');
        // FIXED: Add CORS headers to error response
        if (!id)
          return new Response('Missing id', {
            status: 400,
            headers: corsHeaders,
          });

        await env.DB.prepare('DELETE FROM allowed_users WHERE id = ?')
          .bind(id)
          .run();
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      // Bulk Add Allowed Users (Admin - CSV) - Protected
      if (path === '/api/allowed-users/bulk' && method === 'POST') {
        await authenticate();
        const { usernames } = (await request.json()) as any;
        // FIXED: Add CORS headers to error response
        if (!Array.isArray(usernames))
          return new Response('Invalid data', {
            status: 400,
            headers: corsHeaders,
          });

        const stmt = env.DB.prepare(
          'INSERT OR IGNORE INTO allowed_users (id, username, created_at) VALUES (?, ?, ?)'
        );
        const batch = usernames.map((name: string) =>
          stmt.bind(crypto.randomUUID(), name.trim(), Date.now())
        );

        if (batch.length > 0) await env.DB.batch(batch);

        return new Response(
          JSON.stringify({ success: true, count: batch.length }),
          { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
        );
      }

      // -----------------------------------------------------------------------
      // ADMIN AUTHENTICATION ENDPOINTS
      // -----------------------------------------------------------------------

      // Admin Login - PUBLIC (Generates Token)
      if (path === '/api/admin/login' && method === 'POST') {
        const { username, password } = (await request.json()) as any;

        if (!username || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: 'Username and password required',
            }),
            {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }

        try {
          const user = await env.DB.prepare(
            'SELECT * FROM admin_users WHERE lower(username) = lower(?) AND is_active = 1'
          )
            .bind(username)
            .first();

          if (user) {
            const isValid = await verifyPassword(
              password,
              user.password_hash,
              secretKey
            );

            if (isValid) {
              // Update last login
              await env.DB.prepare(
                'UPDATE admin_users SET last_login = ? WHERE id = ?'
              )
                .bind(Date.now(), user.id)
                .run();

              // Generate JWT
              const token = await signJwt(
                {
                  sub: user.id,
                  username: user.username,
                  exp: Math.floor(Date.now() / 1000) + 24 * 60 * 60, // 24 hours
                },
                jwtSecret
              );

              return new Response(
                JSON.stringify({
                  success: true,
                  username: user.username,
                  token, // Return token
                  message: 'Login successful',
                }),
                {
                  headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json',
                  },
                }
              );
            }
          }

          return new Response(
            JSON.stringify({ success: false, error: 'Invalid credentials' }),
            {
              status: 401,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        } catch (e: any) {
          console.error('Login error:', e);
          return new Response(
            JSON.stringify({ success: false, error: 'Authentication failed: ' + e.message }),
            {
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }
      }

      // Get All Admin Users - Protected
      if (path === '/api/admin/users' && method === 'GET') {
        await authenticate();
        try {
          const { results } = await env.DB.prepare(
            'SELECT id, username, is_active, created_at, last_login FROM admin_users ORDER BY created_at DESC'
          ).all();

          return new Response(JSON.stringify(results), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        } catch (e: any) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }

      // Create New Admin User - Protected
      if (path === '/api/admin/users' && method === 'POST') {
        await authenticate();
        const { username, password } = (await request.json()) as any;

        if (!username || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: 'Username and password required',
            }),
            {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }

        if (password.length < 6) {
          return new Response(
            JSON.stringify({
              success: false,
              error: 'Password must be at least 6 characters',
            }),
            {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }

        try {
          const passwordHash = await hashPassword(password, secretKey);

          await env.DB.prepare(
            'INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)'
          )
            .bind(
              crypto.randomUUID(),
              username.trim(),
              passwordHash,
              Date.now()
            )
            .run();

          return new Response(
            JSON.stringify({ success: true, message: 'Admin user created' }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (e: any) {
          if (e.message?.includes('UNIQUE constraint')) {
            return new Response(
              JSON.stringify({
                success: false,
                error: 'Username already exists',
              }),
              {
                status: 400,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
              }
            );
          }
          return new Response(
            JSON.stringify({ success: false, error: e.message }),
            {
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }
      }

      // Update Admin Password - Protected
      if (path === '/api/admin/users/password' && method === 'PUT') {
        await authenticate();
        const { username, newPassword } = (await request.json()) as any;

        if (!username || !newPassword || newPassword.length < 6) {
          return new Response(
            JSON.stringify({
              success: false,
              error: 'Username and new password (min 6 chars) required',
            }),
            {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }

        try {
          const passwordHash = await hashPassword(newPassword, secretKey);

          const result = await env.DB.prepare(
            'UPDATE admin_users SET password_hash = ? WHERE lower(username) = lower(?)'
          )
            .bind(passwordHash, username)
            .run();

          if (result.success) {
            return new Response(
              JSON.stringify({ success: true, message: 'Password updated' }),
              {
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
              }
            );
          } else {
            return new Response(
              JSON.stringify({ success: false, error: 'User not found' }),
              {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
              }
            );
          }
        } catch (e: any) {
          return new Response(
            JSON.stringify({ success: false, error: e.message }),
            {
              status: 500,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }
      }

      // Delete Admin User - Protected
      if (path === '/api/admin/users' && method === 'DELETE') {
        await authenticate();
        const urlParams = new URL(request.url).searchParams;
        const id = urlParams.get('id');

        // FIXED: Add CORS headers to error response
        if (!id) {
          return new Response('Missing id', {
            status: 400,
            headers: corsHeaders,
          });
        }

        // Prevent deleting the last admin
        const countResult = await env.DB.prepare(
          'SELECT count(*) as count FROM admin_users'
        ).first('count');
        if (countResult && countResult.count <= 1) {
          return new Response(
            JSON.stringify({
              success: false,
              error: 'Cannot delete the last admin user',
            }),
            {
              status: 400,
              headers: { ...corsHeaders, 'Content-Type': 'application/json' },
            }
          );
        }

        try {
          await env.DB.prepare('DELETE FROM admin_users WHERE id = ?')
            .bind(id)
            .run();

          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        } catch (e: any) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }

      // Toggle Admin Active Status - Protected
      if (path === '/api/admin/users/toggle' && method === 'PUT') {
        await authenticate();
        const { id } = (await request.json()) as any;

        // FIXED: Add CORS headers to error response
        if (!id) {
          return new Response('Missing id', {
            status: 400,
            headers: corsHeaders,
          });
        }

        try {
          // Get current status
          const user = await env.DB.prepare(
            'SELECT is_active FROM admin_users WHERE id = ?'
          )
            .bind(id)
            .first();

          if (!user) {
            return new Response(
              JSON.stringify({ success: false, error: 'User not found' }),
              {
                status: 404,
                headers: { ...corsHeaders, 'Content-Type': 'application/json' },
              }
            );
          }

          const newStatus = user.is_active ? 0 : 1;

          // Check if trying to deactivate the last active admin
          if (newStatus === 0) {
            const activeCount = await env.DB.prepare(
              'SELECT count(*) as count FROM admin_users WHERE is_active = 1'
            ).first('count');
            if (activeCount && activeCount.count <= 1) {
              return new Response(
                JSON.stringify({
                  success: false,
                  error: 'Cannot deactivate the last active admin',
                }),
                {
                  status: 400,
                  headers: {
                    ...corsHeaders,
                    'Content-Type': 'application/json',
                  },
                }
              );
            }
          }

          await env.DB.prepare(
            'UPDATE admin_users SET is_active = ? WHERE id = ?'
          )
            .bind(newStatus, id)
            .run();

          return new Response(
            JSON.stringify({ success: true, is_active: newStatus }),
            { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
          );
        } catch (e: any) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, 'Content-Type': 'application/json' },
          });
        }
      }

      // SYSTEM STATUS ENDPOINT (Real Checks) - Protected
      if (path === '/api/system-status' && method === 'GET') {
        await authenticate();
        const status: any = {
          database: { status: 'unknown', message: '' },
          storage: { status: 'unknown', message: '' },
          meta: { status: 'unknown', message: '', appId: '' },
          env: {},
        };

        // 1. Check DB
        try {
          const start = Date.now();
          await env.DB.prepare('SELECT 1').first();
          const latency = Date.now() - start;
          status.database = {
            status: 'connected',
            message: `Latency: ${latency}ms`,
          };
        } catch (e: any) {
          status.database = {
            status: 'error',
            message: e.message || 'Connection failed',
          };
        }

        // 2. Check R2 Storage
        try {
          if (!env.BUCKET) {
            throw new Error('BUCKET binding not found in environment');
          }
          // Try to list 1 object to verify access
          await env.BUCKET.list({ limit: 1 });
          status.storage = {
            status: 'connected',
            message: 'Bucket accessible',
          };
        } catch (e: any) {
          status.storage = {
            status: 'error',
            message: e.message || 'Access denied or misconfigured',
          };
        }

        // 3. Check Meta Config
        if (env.META_APP_ID && env.META_APP_SECRET) {
          status.meta = {
            status: 'configured',
            message: 'Credentials present',
            appId:
              env.META_APP_ID.length > 8
                ? `${env.META_APP_ID.slice(0, 4)}****${env.META_APP_ID.slice(
                    -4
                  )}`
                : '****',
          };
        } else {
          status.meta = {
            status: 'error',
            message: 'Missing App ID or Secret',
            appId: 'N/A',
          };
        }

        // 4. Check Env Vars Existence
        const varsToCheck = [
          'META_APP_ID',
          'META_APP_SECRET',
          'META_REDIRECT_URI',
          'FRONTEND_URL',
          'API_SECRET',
          'ENCRYPTION_KEY',
        ];
        varsToCheck.forEach((key) => {
          status.env[key] = !!(env as any)[key];
        });

        return new Response(JSON.stringify(status), {
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      return new Response('Not Found', { status: 404, headers: corsHeaders });
    } catch (err: any) {
      // Handle authentication errors specifically
      if (err.message === 'Unauthorized' || err.message === 'Token expired') {
        return new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: { ...corsHeaders, 'Content-Type': 'application/json' },
        });
      }

      console.error('Global Worker Error:', err);
      return new Response(
        JSON.stringify({ error: err.message || 'Internal Server Error' }),
        { status: 500, headers: corsHeaders }
      );
    }
  },

  // -----------------------------------------------------------------------------
  // SCHEDULED CRON HANDLER
  // -----------------------------------------------------------------------------
  async scheduled(event: any, env: Env, ctx: any): Promise<void> {
    // 1. Refresh Window: Look for tokens expiring in the next 7 days
    const REFRESH_WINDOW_MS = 604800000;
    const now = Date.now();
    const threshold = now + REFRESH_WINDOW_MS;

    console.log(
      `[Cron] Starting token refresh check. Looking for expiry < ${new Date(
        threshold
      ).toISOString()}`
    );

    try {
      // Find active accounts nearing expiry
      // We select access_token here, which is encrypted
      const { results } = await env.DB.prepare(
        "SELECT id, access_token, fb_page_name FROM accounts WHERE status = 'active' AND token_expires_at < ?"
      )
        .bind(threshold)
        .all();

      if (results.length === 0) {
        console.log('[Cron] No accounts need refreshing.');
        return;
      }

      console.log(`[Cron] Found ${results.length} accounts to refresh.`);

      // 2. Queue Refresh Jobs
      for (const acc of results) {
        await env.QUEUE.send({
          type: 'REFRESH_TOKEN',
          accountId: acc.id,
          currentAccessToken: acc.access_token, // This is encrypted
          pageName: acc.fb_page_name,
        });
      }
    } catch (e: any) {
      console.error('[Cron] Error querying database:', e);
    }
  },

  // -----------------------------------------------------------------------------
  // QUEUE CONSUMER
  // -----------------------------------------------------------------------------
  async queue(batch: any, env: Env): Promise<void> {
    for (const message of batch.messages) {
      const {
        type,
        postId,
        accountId,
        currentAccessToken,
        accounts,
        post,
        retryCount,
      } = message.body;

      try {
        if (type === 'START_POST') {
          await this.handleStartPost(postId, env);
        }

        if (type === 'PROCESS_BATCH') {
          // 'accounts' and 'post' are passed in the message to avoid re-fetching
          await this.processBatch(accounts, post, env);
        }

        if (type === 'REFRESH_TOKEN') {
          await this.handleRefreshToken(accountId, currentAccessToken, env);
        }

        if (type === 'RETRY_ACCOUNT_POST') {
          await this.handleRetryAccountPost(postId, accountId, retryCount, env);
        }
      } catch (err) {
        console.error(`Error processing message type ${type}:`, err);
        message.retry(); // Retry transient failures
      }
    }
  },

  // -----------------------------------------------------------------------------
  // JOB HANDLERS
  // -----------------------------------------------------------------------------

  async handleRefreshToken(
    accountId: string,
    encryptedCurrentToken: string,
    env: Env
  ) {
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;
    try {
      // Decrypt token to use it
      const decryptedToken = await decryptToken(
        encryptedCurrentToken,
        secretKey
      );

      // Exchange current long-lived token for a new one (refresh)
      const refreshUrl = `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${env.META_APP_ID}&client_secret=${env.META_APP_SECRET}&fb_exchange_token=${decryptedToken}`;

      const response = await fetch(refreshUrl);
      const data: any = await response.json();

      if (data.error || !data.access_token) {
        throw new Error(
          data.error?.message || 'Token exchange returned no token'
        );
      }

      const newAccessToken = data.access_token;
      // Expires in comes in seconds, convert to MS. Default 60 days if missing.
      const expiresInMs = data.expires_in ? data.expires_in * 1000 : 5184000000;
      const newExpiry = Date.now() + expiresInMs;

      // Encrypt the new token before saving
      const encryptedNewToken = await encryptToken(newAccessToken, secretKey);

      // Update DB
      await env.DB.prepare(
        "UPDATE accounts SET access_token = ?, token_expires_at = ?, last_updated = ?, status = 'active' WHERE id = ?"
      )
        .bind(encryptedNewToken, newExpiry, Date.now(), accountId)
        .run();

      console.log(`[RefreshToken] Success for account ${accountId}`);
    } catch (error: any) {
      console.error(`[RefreshToken] Failed for account ${accountId}:`, error);

      // If refresh fails, mark as error so user knows to reconnect
      await env.DB.prepare(
        "UPDATE accounts SET status = 'error', last_updated = ? WHERE id = ?"
      )
        .bind(Date.now(), accountId)
        .run();
    }
  },

  async handleStartPost(postId: string, env: Env) {
    // 1. Get Post Data
    const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?')
      .bind(postId)
      .first();
    if (!post) return;

    // 2. Get All Active Accounts (includes encrypted access_token)
    const { results: accounts } = await env.DB.prepare(
      'SELECT * FROM accounts WHERE status = ?'
    )
      .bind('active')
      .all();

    // Update total count and status to 'in_progress'
    await env.DB.prepare(
      'UPDATE posts SET total_accounts = ?, status = ? WHERE id = ?'
    )
      .bind(accounts.length, 'in_progress', postId)
      .run();

    // Handle 0 accounts edge case (immediately complete)
    if (accounts.length === 0) {
      console.log(`[StartPost] No active accounts for post ${postId}. Completing immediately.`);
      await env.DB.prepare(
        "UPDATE posts SET status = 'completed', completed_at = ? WHERE id = ?"
      )
        .bind(Date.now(), postId)
        .run();
      return;
    }

    // 3. Split into chunks of 100
    // Requirement: Divide into 100 accounts for 15 min.
    // We queue each batch with a delay of (index * 15 minutes).
    const chunkSize = 100;
    const delayPerChunkSeconds = 15 * 60; // 15 minutes in seconds

    for (let i = 0; i < accounts.length; i += chunkSize) {
      const chunk = accounts.slice(i, i + chunkSize);
      const batchIndex = Math.floor(i / chunkSize);
      const delay = batchIndex * delayPerChunkSeconds;

      // Send batch to queue with delay
      await env.QUEUE.send(
        {
          type: 'PROCESS_BATCH',
          postId,
          accounts: chunk, // Pass full account objects to avoid re-fetching in consumer
          post, // Pass post data
        },
        {
          delaySeconds: delay, // 0, 900, 1800, etc.
        }
      );
    }
  },

  async processBatch(accounts: any[], post: any, env: Env) {
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;

    for (const account of accounts) {
      // Requirement: "each account should be posted between 2-3 seconds gap"
      // Random delay between 2000ms and 3000ms
      const delay = Math.floor(Math.random() * 1000) + 2000;
      await new Promise((resolve) => setTimeout(resolve, delay));

      // Attempt post with retry logic enabled (retryCount start = 0)
      await this.attemptPost(account, post, secretKey, env, 0);
    }

    // Check completion
    await this.checkCampaignCompletion(post.id, env);
  },

  async handleRetryAccountPost(
    postId: string,
    accountId: string,
    retryCount: number,
    env: Env
  ) {
    const post = await env.DB.prepare('SELECT * FROM posts WHERE id = ?')
      .bind(postId)
      .first();
    const account = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?')
      .bind(accountId)
      .first();

    if (!post || !account) {
      console.error(
        'Retry failed: Data not found for post/account',
        postId,
        accountId
      );
      return;
    }

    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;
    await this.attemptPost(account, post, secretKey, env, retryCount);

    await this.checkCampaignCompletion(postId, env);
  },

  // -----------------------------------------------------------------------------
  // SHARED POSTING LOGIC
  // -----------------------------------------------------------------------------

  async attemptPost(
    account: any,
    post: any,
    secretKey: string,
    env: Env,
    retryCount: number
  ) {
    // Apply Anti-Spam Variations (Shuffle hashtags, inject emojis)
    const finalCaption = processCaption(
      post.base_caption,
      account.fb_page_name
    );

    try {
      const metaIds = await this.publishToMeta(
        account,
        post,
        finalCaption,
        secretKey
      );

      // Log Success
      await env.DB.prepare(
        'INSERT INTO logs (post_id, account_id, final_caption, meta_post_id, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)'
      )
        .bind(post.id, account.id, finalCaption, metaIds, 'success', Date.now())
        .run();

      await env.DB.prepare(
        'UPDATE posts SET success_count = success_count + 1 WHERE id = ?'
      )
        .bind(post.id)
        .run();
    } catch (err: any) {
      const MAX_RETRIES = 5;
      if (retryCount < MAX_RETRIES) {
        // Schedule Retry
        const nextRetry = retryCount + 1;
        const backoffSeconds = Math.pow(2, nextRetry) * 30; // 60s, 120s, 240s, 480s, 960s

        console.log(
          `[Retry] Queuing retry #${nextRetry} for ${account.fb_page_name} (Delay: ${backoffSeconds}s). Reason: ${err.message}`
        );

        await env.QUEUE.send(
          {
            type: 'RETRY_ACCOUNT_POST',
            postId: post.id,
            accountId: account.id,
            retryCount: nextRetry,
          },
          { delaySeconds: backoffSeconds }
        );
      } else {
        // Fail
        console.error(
          `[Failure] Max retries reached for ${account.fb_page_name}.`
        );

        await env.DB.prepare(
          'INSERT INTO logs (post_id, account_id, final_caption, error_message, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)'
        )
          .bind(
            post.id,
            account.id,
            finalCaption,
            `Max Retries Exceeded: ${err.message}`,
            'failed',
            Date.now()
          )
          .run();

        await env.DB.prepare(
          'UPDATE posts SET failure_count = failure_count + 1 WHERE id = ?'
        )
          .bind(post.id)
          .run();
      }
    }
  },

  async publishToMeta(
    account: any,
    post: any,
    caption: string,
    secretKey: string
  ): Promise<string> {
    // Decrypt Token
    let accessToken;
    try {
      accessToken = await decryptToken(account.access_token, secretKey);
    } catch (e) {
      throw new Error('Token decryption failed');
    }

    // 1. Create Media Container (Instagram)
    const containerUrl = `https://graph.facebook.com/v19.0/${account.ig_user_id}/media`;
    const containerResp = await fetch(containerUrl, {
      method: 'POST',
      body: new URLSearchParams({
        image_url: post.public_image_url,
        caption: caption,
        access_token: accessToken,
      }),
    });
    const containerData: any = await containerResp.json();

    if (containerData.error || !containerData.id) {
      throw new Error(
        'IG Container: ' + (containerData.error?.message || 'Unknown error')
      );
    }

    // 2. Publish Media (Instagram)
    const publishUrl = `https://graph.facebook.com/v19.0/${account.ig_user_id}/media_publish`;
    const publishResp = await fetch(publishUrl, {
      method: 'POST',
      body: new URLSearchParams({
        creation_id: containerData.id,
        access_token: accessToken,
      }),
    });
    const publishData: any = await publishResp.json();

    if (publishData.error || !publishData.id) {
      throw new Error(
        'IG Publish: ' + (publishData.error?.message || 'Unknown error')
      );
    }

    // 3. Publish to Facebook Page
    const fbUrl = `https://graph.facebook.com/v19.0/${account.fb_page_id}/photos`;
    const fbResp = await fetch(fbUrl, {
      method: 'POST',
      body: new URLSearchParams({
        url: post.public_image_url,
        caption: caption,
        access_token: accessToken,
        published: 'true',
      }),
    });
    const fbData: any = await fbResp.json();

    return `IG:${publishData.id}, FB:${fbData.id || 'failed'}`;
  },

  async checkCampaignCompletion(postId: string, env: Env) {
    const stats = await env.DB.prepare(
      'SELECT success_count, failure_count, total_accounts FROM posts WHERE id = ?'
    )
      .bind(postId)
      .first();
    if (
      stats &&
      stats.success_count + stats.failure_count >= stats.total_accounts
    ) {
      await env.DB.prepare(
        "UPDATE posts SET status = 'completed', completed_at = ? WHERE id = ? AND status != 'completed'"
      )
        .bind(Date.now(), postId)
        .run();
    }
  },
};
