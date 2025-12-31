var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// .wrangler/tmp/bundle-OXXgyv/checked-fetch.js
var urls = /* @__PURE__ */ new Set();
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
__name(checkURL, "checkURL");
globalThis.fetch = new Proxy(globalThis.fetch, {
  apply(target, thisArg, argArray) {
    const [request, init] = argArray;
    checkURL(request, init);
    return Reflect.apply(target, thisArg, argArray);
  }
});

// worker.ts
async function getCryptoKey(secret) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: enc.encode("social_sync_salt_v1"),
      // In prod, use a random salt stored with data, but fixed here for simplicity
      iterations: 1e5,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}
__name(getCryptoKey, "getCryptoKey");
async function encryptToken(text, secret) {
  if (!text) return "";
  try {
    const key = await getCryptoKey(secret);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(text);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoded
    );
    const toHex = /* @__PURE__ */ __name((buf) => Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join(""), "toHex");
    return `${toHex(iv.buffer)}:${toHex(encrypted)}`;
  } catch (e) {
    console.error("Encryption failed", e);
    throw e;
  }
}
__name(encryptToken, "encryptToken");
async function decryptToken(cipherText, secret) {
  if (!cipherText || !cipherText.includes(":")) return cipherText;
  try {
    const [ivHex, dataHex] = cipherText.split(":");
    const key = await getCryptoKey(secret);
    const fromHex = /* @__PURE__ */ __name((hex) => new Uint8Array(
      (hex.match(/.{1,2}/g) || []).map((byte) => parseInt(byte, 16))
    ), "fromHex");
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: fromHex(ivHex) },
      key,
      fromHex(dataHex)
    );
    return new TextDecoder().decode(decrypted);
  } catch (e) {
    console.error("Decryption failed", e);
    throw new Error("Failed to decrypt token");
  }
}
__name(decryptToken, "decryptToken");
function shuffleArray(array) {
  const arr = [...array];
  for (let i = arr.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [arr[i], arr[j]] = [arr[j], arr[i]];
  }
  return arr;
}
__name(shuffleArray, "shuffleArray");
function processCaption(base, accountName) {
  let caption = base.replace(/\{([^{}]+)\}/g, (_match, group) => {
    const options = group.split("|");
    return options[Math.floor(Math.random() * options.length)];
  });
  const hashtagRegex = /#[\w\u0590-\u05ff]+/g;
  const foundHashtags = caption.match(hashtagRegex) || [];
  let cleanCaption = caption.replace(hashtagRegex, "").trim();
  const shuffledTags = shuffleArray(foundHashtags).join(" ");
  const emojis = [
    "\u2728",
    "\u{1F680}",
    "\u{1F525}",
    "\u{1F4AF}",
    "\u2705",
    "\u{1F4E3}",
    "\u{1F447}",
    "\u{1F440}",
    "\u{1F31F}",
    "\u{1F4AB}",
    "\u26A1",
    "\u{1F4CD}"
  ];
  const numEmojis = Math.floor(Math.random() * 2) + 1;
  const selectedEmojis = shuffleArray(emojis).slice(0, numEmojis);
  const injectionStrategy = Math.random();
  if (injectionStrategy < 0.33) {
    cleanCaption = `${selectedEmojis.join(" ")} ${cleanCaption}`;
  } else if (injectionStrategy < 0.66) {
    cleanCaption = `${cleanCaption} ${selectedEmojis.join(" ")}`;
  } else {
    cleanCaption = cleanCaption.replace(/\n\n/g, `
${selectedEmojis[0]}
`);
  }
  let finalPost = cleanCaption;
  if (shuffledTags.length > 0) {
    finalPost += `

${shuffledTags}`;
  }
  if (Math.random() > 0.9) {
    finalPost += `
\u{1F4CD} ${accountName}`;
  }
  return finalPost;
}
__name(processCaption, "processCaption");
async function hashPassword(password, secretKey) {
  const encoder = new TextEncoder();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  const hashArray = Array.from(new Uint8Array(derivedBits));
  const hashHex = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  const saltHex = Array.from(salt).map((b) => b.toString(16).padStart(2, "0")).join("");
  return `100000:${saltHex}:${hashHex}`;
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, storedHash, secretKey) {
  try {
    const parts = storedHash.split(":");
    if (parts.length !== 3) return false;
    const [iterations, saltHex, hashPart] = parts;
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: Uint8Array.from(
          saltHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
        ),
        iterations: parseInt(iterations),
        hash: "SHA-256"
      },
      keyMaterial,
      256
    );
    const hashArray = Array.from(new Uint8Array(derivedBits));
    const computedHash = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
    return computedHash === hashPart;
  } catch (e) {
    console.error("Password verification failed", e);
    return false;
  }
}
__name(verifyPassword, "verifyPassword");
async function ensureAdminUser(env, secretKey) {
  try {
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
    const existing = await env.DB.prepare(
      "SELECT id FROM admin_users WHERE username = ?"
    ).bind("admin").first();
    if (!existing) {
      const passwordHash = await hashPassword("password", secretKey);
      await env.DB.prepare(
        "INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)"
      ).bind(crypto.randomUUID(), "admin", passwordHash, Date.now()).run();
      console.log("Created default admin user: admin / password");
    }
  } catch (e) {
    console.error("Failed to ensure admin user:", e);
  }
}
__name(ensureAdminUser, "ensureAdminUser");
var worker_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, Authorization"
    };
    if (method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;
    await ensureAdminUser(env, secretKey);
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
    }
    try {
      if (path === "/api/auth/login" && method === "GET") {
        const source = url.searchParams.get("source") || "admin";
        const state = JSON.stringify({ source });
        const metaUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${env.META_APP_ID}&redirect_uri=${env.META_REDIRECT_URI}&state=${encodeURIComponent(
          state
        )}&scope=pages_show_list,pages_read_engagement,pages_manage_posts,instagram_basic,instagram_content_publish&response_type=code`;
        return Response.redirect(metaUrl, 302);
      }
      if (path === "/api/auth/callback" && method === "GET") {
        const code = url.searchParams.get("code");
        const error = url.searchParams.get("error");
        const stateStr = url.searchParams.get("state");
        let redirectBase = "#accounts";
        if (stateStr) {
          try {
            const state = JSON.parse(decodeURIComponent(stateStr));
            if (state.source === "onboarding") {
              redirectBase = "#onboarding";
            }
          } catch (e) {
            console.warn("Failed to parse state", e);
          }
        }
        const frontendUrl = env.FRONTEND_URL || "http://localhost:3000";
        if (error || !code) {
          return Response.redirect(
            `${frontendUrl}/${redirectBase}?error=auth_failed`,
            302
          );
        }
        const tokenResp = await fetch(
          `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${env.META_APP_ID}&redirect_uri=${env.META_REDIRECT_URI}&client_secret=${env.META_APP_SECRET}&code=${code}`
        );
        const tokenData = await tokenResp.json();
        if (!tokenData.access_token) {
          return Response.redirect(
            `${frontendUrl}/${redirectBase}?error=token_failed`,
            302
          );
        }
        const longTokenResp = await fetch(
          `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${env.META_APP_ID}&client_secret=${env.META_APP_SECRET}&fb_exchange_token=${tokenData.access_token}`
        );
        const longTokenData = await longTokenResp.json();
        const finalToken = longTokenData.access_token || tokenData.access_token;
        const expiry = Date.now() + (longTokenData.expires_in ? longTokenData.expires_in * 1e3 : 5184e6);
        const accountsResp = await fetch(
          `https://graph.facebook.com/v19.0/me/accounts?fields=name,access_token,instagram_business_account{id,username}&access_token=${finalToken}`
        );
        const accountsData = await accountsResp.json();
        let connectedCount = 0;
        const stmt = env.DB.prepare(
          `INSERT OR REPLACE INTO accounts (id, owner_name, fb_page_id, fb_page_name, ig_user_id, ig_username, access_token, token_expires_at, status, created_at, last_updated) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        );
        const batch = [];
        if (accountsData.data) {
          for (const page of accountsData.data) {
            if (page.instagram_business_account) {
              const encryptedPageToken = await encryptToken(
                page.access_token,
                secretKey
              );
              batch.push(
                stmt.bind(
                  crypto.randomUUID(),
                  "Unknown Owner",
                  // In real app, fetch user profile to get real name
                  page.id,
                  page.name,
                  page.instagram_business_account.id,
                  page.instagram_business_account.username || "unknown",
                  // Store IG Handle
                  encryptedPageToken,
                  // Store Encrypted PAGE Token
                  expiry,
                  "active",
                  Date.now(),
                  Date.now()
                )
              );
              connectedCount++;
            }
          }
        }
        if (batch.length > 0) await env.DB.batch(batch);
        return Response.redirect(
          `${frontendUrl}/${redirectBase}?success=true&count=${connectedCount}`,
          302
        );
      }
      if (path === "/api/accounts" && method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT id, owner_name, fb_page_name, ig_username, status, last_updated FROM accounts ORDER BY created_at DESC"
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/dashboard-stats" && method === "GET") {
        const totalAccounts = await env.DB.prepare(
          "SELECT count(*) as count FROM accounts"
        ).first("count");
        const activeAccounts = await env.DB.prepare(
          "SELECT count(*) as count FROM accounts WHERE status = 'active'"
        ).first("count");
        const failedTokens = await env.DB.prepare(
          "SELECT count(*) as count FROM accounts WHERE status = 'error'"
        ).first("count");
        const oneWeekAgo = Date.now() - 7 * 24 * 60 * 60 * 1e3;
        const postsCount = await env.DB.prepare(
          "SELECT count(*) as count FROM posts WHERE created_at > ?"
        ).bind(oneWeekAgo).first("count");
        return new Response(
          JSON.stringify({
            totalAccounts,
            activeAccounts,
            failedTokens,
            postsCount,
            chartData: []
            // TODO: Implement day-by-day aggregation query if D1 allows
          }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (path === "/api/posts" && method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT * FROM posts ORDER BY created_at DESC"
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/logs" && method === "GET") {
        const postId = url.searchParams.get("postId");
        if (!postId) return new Response("Missing postId", { status: 400 });
        const { results } = await env.DB.prepare(
          `
              SELECT l.*, a.fb_page_name as account_name 
              FROM logs l 
              LEFT JOIN accounts a ON l.account_id = a.id 
              WHERE l.post_id = ? 
              ORDER BY l.timestamp DESC
          `
        ).bind(postId).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/upload" && method === "POST") {
        try {
          const formData = await request.formData();
          const file = formData.get("file");
          if (!file || !(file instanceof File)) {
            return new Response("No valid file uploaded", { status: 400 });
          }
          const key = `uploads/${crypto.randomUUID()}-${file.name.replace(
            /[^a-zA-Z0-9.-]/g,
            ""
          )}`;
          await env.BUCKET.put(key, file.stream(), {
            httpMetadata: { contentType: file.type }
          });
          const publicUrl = `${url.origin}/images/${key}`;
          return new Response(JSON.stringify({ url: publicUrl }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (e) {
          console.error("Upload failed", e);
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: corsHeaders
          });
        }
      }
      if (path.startsWith("/images/") && method === "GET") {
        const key = path.replace("/images/", "");
        const object = await env.BUCKET.get(key);
        if (!object) return new Response("Not Found", { status: 404 });
        const headers = new Headers();
        object.writeHttpMetadata(headers);
        headers.set("etag", object.httpEtag);
        return new Response(object.body, { headers });
      }
      if (path === "/api/posts" && method === "POST") {
        const body = await request.json();
        const postId = crypto.randomUUID();
        await env.DB.prepare(
          "INSERT INTO posts (id, public_image_url, base_caption, status, created_at, success_count, failure_count, total_accounts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(
          postId,
          body.imageUrl,
          body.caption,
          "pending",
          Date.now(),
          0,
          0,
          0
        ).run();
        await env.QUEUE.send({ type: "START_POST", postId });
        return new Response(JSON.stringify({ success: true, postId }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/verify-user" && method === "POST") {
        const { username } = await request.json();
        if (!username) return new Response("Missing username", { status: 400 });
        const user = await env.DB.prepare(
          "SELECT * FROM allowed_users WHERE lower(username) = lower(?)"
        ).bind(username).first();
        if (user) {
          return new Response(
            JSON.stringify({ verified: true, username: user.username }),
            { headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        } else {
          return new Response(JSON.stringify({ verified: false }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      if (path === "/api/allowed-users" && method === "GET") {
        const { results } = await env.DB.prepare(
          "SELECT * FROM allowed_users ORDER BY created_at DESC"
        ).all();
        return new Response(JSON.stringify(results), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/allowed-users" && method === "POST") {
        const { username } = await request.json();
        if (!username) return new Response("Missing username", { status: 400 });
        try {
          await env.DB.prepare(
            "INSERT INTO allowed_users (id, username, created_at) VALUES (?, ?, ?)"
          ).bind(crypto.randomUUID(), username.trim(), Date.now()).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "User likely already exists"
            }),
            { headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        }
      }
      if (path === "/api/allowed-users" && method === "DELETE") {
        const urlParams = new URL(request.url).searchParams;
        const id = urlParams.get("id");
        if (!id) return new Response("Missing id", { status: 400 });
        await env.DB.prepare("DELETE FROM allowed_users WHERE id = ?").bind(id).run();
        return new Response(JSON.stringify({ success: true }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      if (path === "/api/allowed-users/bulk" && method === "POST") {
        const { usernames } = await request.json();
        if (!Array.isArray(usernames))
          return new Response("Invalid data", { status: 400 });
        const stmt = env.DB.prepare(
          "INSERT OR IGNORE INTO allowed_users (id, username, created_at) VALUES (?, ?, ?)"
        );
        const batch = usernames.map(
          (name) => stmt.bind(crypto.randomUUID(), name.trim(), Date.now())
        );
        if (batch.length > 0) await env.DB.batch(batch);
        return new Response(
          JSON.stringify({ success: true, count: batch.length }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      if (path === "/api/admin/login" && method === "POST") {
        const { username, password } = await request.json();
        if (!username || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username and password required"
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
        try {
          const user = await env.DB.prepare(
            "SELECT * FROM admin_users WHERE lower(username) = lower(?) AND is_active = 1"
          ).bind(username).first();
          if (user) {
            const isValid = await verifyPassword(
              password,
              user.password_hash,
              secretKey
            );
            if (isValid) {
              await env.DB.prepare(
                "UPDATE admin_users SET last_login = ? WHERE id = ?"
              ).bind(Date.now(), user.id).run();
              return new Response(
                JSON.stringify({
                  success: true,
                  username: user.username,
                  message: "Login successful"
                }),
                {
                  headers: {
                    ...corsHeaders,
                    "Content-Type": "application/json"
                  }
                }
              );
            }
          }
          return new Response(
            JSON.stringify({ success: false, error: "Invalid credentials" }),
            {
              status: 401,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        } catch (e) {
          console.error("Login error:", e);
          return new Response(
            JSON.stringify({ success: false, error: "Authentication failed" }),
            {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
      }
      if (path === "/api/admin/users" && method === "GET") {
        try {
          const { results } = await env.DB.prepare(
            "SELECT id, username, is_active, created_at, last_login FROM admin_users ORDER BY created_at DESC"
          ).all();
          return new Response(JSON.stringify(results), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      if (path === "/api/admin/users" && method === "POST") {
        const { username, password } = await request.json();
        if (!username || !password) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username and password required"
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
        if (password.length < 6) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Password must be at least 6 characters"
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
        try {
          const passwordHash = await hashPassword(password, secretKey);
          await env.DB.prepare(
            "INSERT INTO admin_users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)"
          ).bind(
            crypto.randomUUID(),
            username.trim(),
            passwordHash,
            Date.now()
          ).run();
          return new Response(
            JSON.stringify({ success: true, message: "Admin user created" }),
            { headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        } catch (e) {
          if (e.message?.includes("UNIQUE constraint")) {
            return new Response(
              JSON.stringify({
                success: false,
                error: "Username already exists"
              }),
              {
                status: 400,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
              }
            );
          }
          return new Response(
            JSON.stringify({ success: false, error: e.message }),
            {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
      }
      if (path === "/api/admin/users/password" && method === "PUT") {
        const { username, newPassword } = await request.json();
        if (!username || !newPassword || newPassword.length < 6) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Username and new password (min 6 chars) required"
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
        try {
          const passwordHash = await hashPassword(newPassword, secretKey);
          const result = await env.DB.prepare(
            "UPDATE admin_users SET password_hash = ? WHERE lower(username) = lower(?)"
          ).bind(passwordHash, username).run();
          if (result.success) {
            return new Response(
              JSON.stringify({ success: true, message: "Password updated" }),
              {
                headers: { ...corsHeaders, "Content-Type": "application/json" }
              }
            );
          } else {
            return new Response(
              JSON.stringify({ success: false, error: "User not found" }),
              {
                status: 404,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
              }
            );
          }
        } catch (e) {
          return new Response(
            JSON.stringify({ success: false, error: e.message }),
            {
              status: 500,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
      }
      if (path === "/api/admin/users" && method === "DELETE") {
        const urlParams = new URL(request.url).searchParams;
        const id = urlParams.get("id");
        if (!id) {
          return new Response("Missing id", {
            status: 400,
            headers: corsHeaders
          });
        }
        const countResult = await env.DB.prepare(
          "SELECT count(*) as count FROM admin_users"
        ).first("count");
        if (countResult && countResult.count <= 1) {
          return new Response(
            JSON.stringify({
              success: false,
              error: "Cannot delete the last admin user"
            }),
            {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            }
          );
        }
        try {
          await env.DB.prepare("DELETE FROM admin_users WHERE id = ?").bind(id).run();
          return new Response(JSON.stringify({ success: true }), {
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      if (path === "/api/admin/users/toggle" && method === "PUT") {
        const { id } = await request.json();
        if (!id) {
          return new Response("Missing id", {
            status: 400,
            headers: corsHeaders
          });
        }
        try {
          const user = await env.DB.prepare(
            "SELECT is_active FROM admin_users WHERE id = ?"
          ).bind(id).first();
          if (!user) {
            return new Response(
              JSON.stringify({ success: false, error: "User not found" }),
              {
                status: 404,
                headers: { ...corsHeaders, "Content-Type": "application/json" }
              }
            );
          }
          const newStatus = user.is_active ? 0 : 1;
          if (newStatus === 0) {
            const activeCount = await env.DB.prepare(
              "SELECT count(*) as count FROM admin_users WHERE is_active = 1"
            ).first("count");
            if (activeCount && activeCount.count <= 1) {
              return new Response(
                JSON.stringify({
                  success: false,
                  error: "Cannot deactivate the last active admin"
                }),
                {
                  status: 400,
                  headers: {
                    ...corsHeaders,
                    "Content-Type": "application/json"
                  }
                }
              );
            }
          }
          await env.DB.prepare(
            "UPDATE admin_users SET is_active = ? WHERE id = ?"
          ).bind(newStatus, id).run();
          return new Response(
            JSON.stringify({ success: true, is_active: newStatus }),
            { headers: { ...corsHeaders, "Content-Type": "application/json" } }
          );
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), {
            status: 500,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
      }
      if (path === "/api/system-status" && method === "GET") {
        const status = {
          database: { status: "unknown", message: "" },
          storage: { status: "unknown", message: "" },
          meta: { status: "unknown", message: "", appId: "" },
          env: {}
        };
        try {
          const start = Date.now();
          await env.DB.prepare("SELECT 1").first();
          const latency = Date.now() - start;
          status.database = {
            status: "connected",
            message: `Latency: ${latency}ms`
          };
        } catch (e) {
          status.database = {
            status: "error",
            message: e.message || "Connection failed"
          };
        }
        try {
          if (!env.BUCKET) {
            throw new Error("BUCKET binding not found in environment");
          }
          await env.BUCKET.list({ limit: 1 });
          status.storage = {
            status: "connected",
            message: "Bucket accessible"
          };
        } catch (e) {
          status.storage = {
            status: "error",
            message: e.message || "Access denied or misconfigured"
          };
        }
        if (env.META_APP_ID && env.META_APP_SECRET) {
          status.meta = {
            status: "configured",
            message: "Credentials present",
            appId: env.META_APP_ID.length > 8 ? `${env.META_APP_ID.slice(0, 4)}****${env.META_APP_ID.slice(
              -4
            )}` : "****"
          };
        } else {
          status.meta = {
            status: "error",
            message: "Missing App ID or Secret",
            appId: "N/A"
          };
        }
        const varsToCheck = [
          "META_APP_ID",
          "META_APP_SECRET",
          "META_REDIRECT_URI",
          "FRONTEND_URL",
          "API_SECRET",
          "ENCRYPTION_KEY"
        ];
        varsToCheck.forEach((key) => {
          status.env[key] = !!env[key];
        });
        return new Response(JSON.stringify(status), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
      return new Response("Not Found", { status: 404, headers: corsHeaders });
    } catch (err) {
      console.error("Global Worker Error:", err);
      return new Response(
        JSON.stringify({ error: err.message || "Internal Server Error" }),
        { status: 500, headers: corsHeaders }
      );
    }
  },
  // -----------------------------------------------------------------------------
  // SCHEDULED CRON HANDLER
  // -----------------------------------------------------------------------------
  async scheduled(event, env, ctx) {
    const REFRESH_WINDOW_MS = 6048e5;
    const now = Date.now();
    const threshold = now + REFRESH_WINDOW_MS;
    console.log(
      `[Cron] Starting token refresh check. Looking for expiry < ${new Date(
        threshold
      ).toISOString()}`
    );
    try {
      const { results } = await env.DB.prepare(
        "SELECT id, access_token, fb_page_name FROM accounts WHERE status = 'active' AND token_expires_at < ?"
      ).bind(threshold).all();
      if (results.length === 0) {
        console.log("[Cron] No accounts need refreshing.");
        return;
      }
      console.log(`[Cron] Found ${results.length} accounts to refresh.`);
      for (const acc of results) {
        await env.QUEUE.send({
          type: "REFRESH_TOKEN",
          accountId: acc.id,
          currentAccessToken: acc.access_token,
          // This is encrypted
          pageName: acc.fb_page_name
        });
      }
    } catch (e) {
      console.error("[Cron] Error querying database:", e);
    }
  },
  // -----------------------------------------------------------------------------
  // QUEUE CONSUMER
  // -----------------------------------------------------------------------------
  async queue(batch, env) {
    for (const message of batch.messages) {
      const {
        type,
        postId,
        accountId,
        currentAccessToken,
        accounts,
        post,
        retryCount
      } = message.body;
      try {
        if (type === "START_POST") {
          await this.handleStartPost(postId, env);
        }
        if (type === "PROCESS_BATCH") {
          await this.processBatch(accounts, post, env);
        }
        if (type === "REFRESH_TOKEN") {
          await this.handleRefreshToken(accountId, currentAccessToken, env);
        }
        if (type === "RETRY_ACCOUNT_POST") {
          await this.handleRetryAccountPost(postId, accountId, retryCount, env);
        }
      } catch (err) {
        console.error(`Error processing message type ${type}:`, err);
        message.retry();
      }
    }
  },
  // -----------------------------------------------------------------------------
  // JOB HANDLERS
  // -----------------------------------------------------------------------------
  async handleRefreshToken(accountId, encryptedCurrentToken, env) {
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;
    try {
      const decryptedToken = await decryptToken(
        encryptedCurrentToken,
        secretKey
      );
      const refreshUrl = `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${env.META_APP_ID}&client_secret=${env.META_APP_SECRET}&fb_exchange_token=${decryptedToken}`;
      const response = await fetch(refreshUrl);
      const data = await response.json();
      if (data.error || !data.access_token) {
        throw new Error(
          data.error?.message || "Token exchange returned no token"
        );
      }
      const newAccessToken = data.access_token;
      const expiresInMs = data.expires_in ? data.expires_in * 1e3 : 5184e6;
      const newExpiry = Date.now() + expiresInMs;
      const encryptedNewToken = await encryptToken(newAccessToken, secretKey);
      await env.DB.prepare(
        "UPDATE accounts SET access_token = ?, token_expires_at = ?, last_updated = ?, status = 'active' WHERE id = ?"
      ).bind(encryptedNewToken, newExpiry, Date.now(), accountId).run();
      console.log(`[RefreshToken] Success for account ${accountId}`);
    } catch (error) {
      console.error(`[RefreshToken] Failed for account ${accountId}:`, error);
      await env.DB.prepare(
        "UPDATE accounts SET status = 'error', last_updated = ? WHERE id = ?"
      ).bind(Date.now(), accountId).run();
    }
  },
  async handleStartPost(postId, env) {
    const post = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
    if (!post) return;
    const { results: accounts } = await env.DB.prepare(
      "SELECT * FROM accounts WHERE status = ?"
    ).bind("active").all();
    await env.DB.prepare(
      "UPDATE posts SET total_accounts = ?, status = ? WHERE id = ?"
    ).bind(accounts.length, "in_progress", postId).run();
    const chunkSize = 100;
    const delayPerChunkSeconds = 15 * 60;
    for (let i = 0; i < accounts.length; i += chunkSize) {
      const chunk = accounts.slice(i, i + chunkSize);
      const batchIndex = Math.floor(i / chunkSize);
      const delay = batchIndex * delayPerChunkSeconds;
      await env.QUEUE.send(
        {
          type: "PROCESS_BATCH",
          postId,
          accounts: chunk,
          // Pass full account objects to avoid re-fetching in consumer
          post
          // Pass post data
        },
        {
          delaySeconds: delay
          // 0, 900, 1800, etc.
        }
      );
    }
  },
  async processBatch(accounts, post, env) {
    const secretKey = env.ENCRYPTION_KEY || env.API_SECRET;
    for (const account of accounts) {
      const delay = Math.floor(Math.random() * 1e3) + 2e3;
      await new Promise((resolve) => setTimeout(resolve, delay));
      await this.attemptPost(account, post, secretKey, env, 0);
    }
    await this.checkCampaignCompletion(post.id, env);
  },
  async handleRetryAccountPost(postId, accountId, retryCount, env) {
    const post = await env.DB.prepare("SELECT * FROM posts WHERE id = ?").bind(postId).first();
    const account = await env.DB.prepare("SELECT * FROM accounts WHERE id = ?").bind(accountId).first();
    if (!post || !account) {
      console.error(
        "Retry failed: Data not found for post/account",
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
  async attemptPost(account, post, secretKey, env, retryCount) {
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
      await env.DB.prepare(
        "INSERT INTO logs (post_id, account_id, final_caption, meta_post_id, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(post.id, account.id, finalCaption, metaIds, "success", Date.now()).run();
      await env.DB.prepare(
        "UPDATE posts SET success_count = success_count + 1 WHERE id = ?"
      ).bind(post.id).run();
    } catch (err) {
      const MAX_RETRIES = 5;
      if (retryCount < MAX_RETRIES) {
        const nextRetry = retryCount + 1;
        const backoffSeconds = Math.pow(2, nextRetry) * 30;
        console.log(
          `[Retry] Queuing retry #${nextRetry} for ${account.fb_page_name} (Delay: ${backoffSeconds}s). Reason: ${err.message}`
        );
        await env.QUEUE.send(
          {
            type: "RETRY_ACCOUNT_POST",
            postId: post.id,
            accountId: account.id,
            retryCount: nextRetry
          },
          { delaySeconds: backoffSeconds }
        );
      } else {
        console.error(
          `[Failure] Max retries reached for ${account.fb_page_name}.`
        );
        await env.DB.prepare(
          "INSERT INTO logs (post_id, account_id, final_caption, error_message, status, timestamp) VALUES (?, ?, ?, ?, ?, ?)"
        ).bind(
          post.id,
          account.id,
          finalCaption,
          `Max Retries Exceeded: ${err.message}`,
          "failed",
          Date.now()
        ).run();
        await env.DB.prepare(
          "UPDATE posts SET failure_count = failure_count + 1 WHERE id = ?"
        ).bind(post.id).run();
      }
    }
  },
  async publishToMeta(account, post, caption, secretKey) {
    let accessToken;
    try {
      accessToken = await decryptToken(account.access_token, secretKey);
    } catch (e) {
      throw new Error("Token decryption failed");
    }
    const containerUrl = `https://graph.facebook.com/v19.0/${account.ig_user_id}/media`;
    const containerResp = await fetch(containerUrl, {
      method: "POST",
      body: new URLSearchParams({
        image_url: post.public_image_url,
        caption,
        access_token: accessToken
      })
    });
    const containerData = await containerResp.json();
    if (containerData.error || !containerData.id) {
      throw new Error(
        "IG Container: " + (containerData.error?.message || "Unknown error")
      );
    }
    const publishUrl = `https://graph.facebook.com/v19.0/${account.ig_user_id}/media_publish`;
    const publishResp = await fetch(publishUrl, {
      method: "POST",
      body: new URLSearchParams({
        creation_id: containerData.id,
        access_token: accessToken
      })
    });
    const publishData = await publishResp.json();
    if (publishData.error || !publishData.id) {
      throw new Error(
        "IG Publish: " + (publishData.error?.message || "Unknown error")
      );
    }
    const fbUrl = `https://graph.facebook.com/v19.0/${account.fb_page_id}/photos`;
    const fbResp = await fetch(fbUrl, {
      method: "POST",
      body: new URLSearchParams({
        url: post.public_image_url,
        caption,
        access_token: accessToken,
        published: "true"
      })
    });
    const fbData = await fbResp.json();
    return `IG:${publishData.id}, FB:${fbData.id || "failed"}`;
  },
  async checkCampaignCompletion(postId, env) {
    const stats = await env.DB.prepare(
      "SELECT success_count, failure_count, total_accounts FROM posts WHERE id = ?"
    ).bind(postId).first();
    if (stats && stats.success_count + stats.failure_count >= stats.total_accounts) {
      await env.DB.prepare(
        "UPDATE posts SET status = 'completed', completed_at = ? WHERE id = ? AND status != 'completed'"
      ).bind(Date.now(), postId).run();
    }
  }
};

// ../../../../Users/manju/.npm/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// ../../../../Users/manju/.npm/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-OXXgyv/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// ../../../../Users/manju/.npm/_npx/32026684e21afda6/node_modules/wrangler/templates/middleware/common.ts
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-OXXgyv/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
