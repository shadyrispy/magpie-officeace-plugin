// The renewals: the temporary AK/SK end in a day and are renewed from the
// refresh token (a DPoP-signed post), a request's renewal and magpie's
// auth.refresh spend the rotating refresh token once between them.
import { test, expect, afterEach } from "bun:test"
import { OfficeAceAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
const offline = async () => { throw new Error("no network in tests") }
afterEach(() => {
  globalThis.fetch = offline
  _internal.renewing.clear()
  _internal.renewed.clear()
})
globalThis.fetch = offline

const ok = (data) => new Response(JSON.stringify(data), { status: 200 })

// serve answers the token endpoint (after gate, when given) and chats
function serve(answer, gate) {
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url))
    calls.push({ url: u, headers: new Headers(init?.headers), init })
    if (u.pathname === "/v1/oauth2/tokens") {
      if (gate) await gate
      return answer(init)
    }
    return new Response("data: [DONE]\n\n", { headers: { "content-type": "text/event-stream" } })
  }
  return calls
}
const refreshes = (calls) => calls.filter((c) => c.url.pathname === "/v1/oauth2/tokens")

const soon = () => Date.now() + 60 * 1000 // past EARLY_MS
// a real P-256 pair: the DPoP proof is signed with it, so the JWK the
// WebCrypto imports has to be a valid one
const pair = await _internal.dpopKeyPair()
const auth = (over = {}) => ({
  type: "oauth", access: "old-ak", secret: "old-sk", securityToken: "st", projectId: "p",
  expires: soon(), refresh: "r1", refreshExpiresAt: Date.now() + 30 * 24 * 3600 * 1000,
  uid: "u1", baseUrl: "https://gw.example/v2", appKey: "key1", appSecret: "sec1",
  dpopPrivateJwk: pair.privateJwk,
  dpopPublicJwk: pair.publicJwk,
  ...over,
})
const NEW = {
  credentials: { access_key_id: "new-ak", secret_access_key: "new-sk", security_token: "st2", project_id: "p", expiration: new Date(Date.now() + 24 * 3600 * 1000).toISOString() },
  refresh_token: "r2",
  refresh_expires_at: new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString(),
}

test("auth.refresh renews ahead of time and gives the changed fields", async () => {
  const calls = serve(() => ok(NEW))
  const sets = []
  const hooks = await OfficeAceAuthPlugin({ client: { auth: { set: async (x) => sets.push(x) } } })
  expect(hooks.auth.refreshLead).toBeGreaterThanOrEqual(60 * 1000)
  const got = await hooks.auth.refresh(auth(), "officeace")
  expect(got.access).toBe("new-ak")
  expect(got.secret).toBe("new-sk")
  expect(got.refresh).toBe("r2")
  expect(got.expires).toBeGreaterThan(Date.now())
  expect("type" in got).toBe(false)
  expect("baseUrl" in got).toBe(false)
  expect(sets).toEqual([]) // magpie saves what the hook gave
  const r = refreshes(calls)
  expect(r.length).toBe(1)
  expect(r[0].url.origin).toBe("https://sts.cn-north-4.myhuaweicloud.com")
  expect(String(r[0].init.body)).toContain("grant_type=refresh_token")
  expect(String(r[0].init.body)).toContain("refresh_token=r1")
  expect(r[0].headers.get("DPoP")).toBeTruthy()
})

test("auth.refresh and a request's renewal at once spend the refresh token once", async () => {
  let open
  const gate = new Promise((ok) => (open = ok))
  const calls = serve(() => ok(NEW), gate)
  const sets = []
  const hooks = await OfficeAceAuthPlugin({ client: { auth: { set: async (x) => sets.push(x) } } })
  const stored = auth({ expires: Date.now() + 1000 }) // stale for a request too
  const opts = await hooks.auth.loader(async () => stored)
  const req = opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: '{"messages":[]}' })
  const hook = hooks.auth.refresh(stored, "officeace")
  await new Promise((ok) => setTimeout(ok, 10))
  open()
  const [res, got] = await Promise.all([req, hook])
  expect(res.status).toBe(200)
  expect(got.access).toBe("new-ak")
  expect(refreshes(calls).length).toBe(1)
  // saved at most once: by the request when it spent the token, else by magpie
  expect(sets.length).toBeLessThanOrEqual(1)
})

test("a refresh token the STS refuses as used is said plainly", async () => {
  const calls = serve(() => new Response(JSON.stringify({ error_code: "STS5.1806", error_msg: "the refresh token has been used" }), { status: 400 }))
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const e = await hooks.auth.refresh(auth(), "officeace").catch((e) => e)
  expect(e).toBeInstanceOf(Error)
  expect(e.message).toContain("has been used")
  expect(e.message).toContain("sign in again")
  expect(refreshes(calls).length).toBe(1)
  // the next renewal tries again (magpie retries in 30s; a fresh sign-in
  // brings a fresh token) — but only after the minute a concurrent one answers for
  globalThis.fetch = offline
})

test("a refresh token past its end marks the sign-in expired", async () => {
  serve(() => ok(NEW))
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const e = await hooks.auth.refresh(auth({ refreshExpiresAt: Date.now() - 1000 }), "officeace").catch((e) => e)
  expect(e).toBeInstanceOf(Error)
  expect(e.signIn).toBe("expired")
})

test("nothing to renew with gives nothing", async () => {
  const calls = serve(() => ok(NEW))
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  // an api auth, an oauth without a DPoP key, an oauth without a token
  expect(await hooks.auth.refresh({ type: "api", key: "k" }, "officeace")).toBeUndefined()
  expect(await hooks.auth.refresh(auth({ dpopPrivateJwk: null, access: "a", secret: "s" }), "officeace")).toBeUndefined()
  expect(await hooks.auth.refresh(auth({ refresh: "" }), "officeace")).toBeUndefined()
  expect(refreshes(calls).length).toBe(0)
})

test("a request renews stale credentials and saves them; a fresh one doesn't", async () => {
  const calls = serve(() => ok(NEW))
  const sets = []
  const hooks = await OfficeAceAuthPlugin({ client: { auth: { set: async (x) => sets.push(x) } } })
  const opts = await hooks.auth.loader(async () => auth())
  await opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: '{"messages":[]}' })
  const chat = calls.find((c) => c.url.pathname === "/v2/chat/completions")
  expect(chat.headers.get("authorization")).toBe("Basic " + Buffer.from("key1:sec1").toString("base64"))
  expect(refreshes(calls).length).toBe(1)
  expect(sets.length).toBe(1)
  expect(sets[0].path).toEqual({ id: "officeace" })
  expect(sets[0].body.access).toBe("new-ak")

  // credentials not near their end: no renewal, no save
  const freshOpts = await hooks.auth.loader(async () => auth({ expires: Date.now() + 20 * 3600 * 1000 }))
  await freshOpts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: '{"messages":[]}' })
  expect(refreshes(calls).length).toBe(1)
  expect(sets.length).toBe(1)
})

test("a failed renewal leaves the credentials there are", async () => {
  serve(() => new Response("busy", { status: 503 }))
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const opts = await hooks.auth.loader(async () => auth())
  const res = await opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: '{"messages":[]}' })
  expect(res.status).toBe(200)
})

test("credentials gone and nothing to renew with is said, the chat failing", async () => {
  globalThis.fetch = async () => new Response("data: [DONE]\n\n", { headers: { "content-type": "text/event-stream" } })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  // no credentials, no DPoP key: nothing a renewal could try
  const opts = await hooks.auth.loader(async () => auth({ access: "", secret: "", expires: Date.now() - 1000, dpopPrivateJwk: null }))
  await expect(opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: "{}" })).rejects.toThrow("credentials have ended")
})
