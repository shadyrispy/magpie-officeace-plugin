// The browser sign-in: Huawei Cloud's page, the code polled for as the
// desktop app does, the exchange, the gateway the permission check names.
import { test, expect, afterEach } from "bun:test"
import { OfficeAceAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const ok = (data) => new Response(JSON.stringify(data), { status: 200 })

// serve routes paths to answers; the routes see nothing but their path here
function serve(routes) {
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url))
    calls.push({ url: u, init, headers: new Headers(init?.headers) })
    const r = routes[u.pathname]
    if (!r) return new Response("", { status: 404 })
    return typeof r === "function" ? r(init) : r
  }
  return calls
}

// a token endpoint answer, as STS gives it
const TOKENS = {
  credentials: {
    access_key_id: "AK1",
    secret_access_key: "SK1",
    security_token: "st1",
    project_id: "proj1",
    expiration: "2026-10-13T00:00:00Z",
  },
  refresh_token: "r1",
  refresh_expires_at: "2026-11-12T00:00:00Z",
  id_token: `.${Buffer.from(JSON.stringify({ sub: "uid-1", preferred_username: "旅行者" })).toString("base64url")}.`,
}

test("authorize opens the page and callback finishes by itself", async () => {
  const calls = serve({
    "/v1/claw/auth/state": () => ok({ state: "s1" }),
    "/v1/claw/auth/code": () => ok({ code: "c1" }),
    "/v1/oauth2/tokens": () => ok(TOKENS),
    "/v1/claw/client-permission-validate": () => ok({
      account_id: "acc11112222333344445555666677778888",
      principal_id: "pid-1",
      model_info: {
        model_api_url_base: "modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com",
        model_auth_info: { model_app_key: "key1", model_app_secret: "sec1" },
      },
    }),
  })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const m = hooks.auth.methods.find((x) => x.label === "OfficeAce account (browser)")
  const step = await m.authorize()
  expect(step.url.startsWith("https://auth.huaweicloud.com/authui/login.html")).toBe(true)
  const inner = new URL(decodeURIComponent(/service=([^&]+)/.exec(step.url)[1]))
  expect(inner.pathname).toBe("/authui/v1/oauth2/authorize")
  expect(inner.searchParams.get("client_id")).toBe(_internal.CLIENT_ID)
  expect(inner.searchParams.get("response_type")).toBe("code")
  expect(inner.searchParams.get("code_challenge_method")).toBe("SHA-256")
  expect(inner.searchParams.get("redirect_uri")).toBe(_internal.REDIRECT_URI)
  expect(step.method).toBe("auto")

  const done = await step.callback()
  expect(done.type).toBe("success")
  expect(done.access).toBe("AK1")
  expect(done.secret).toBe("SK1")
  expect(done.refresh).toBe("r1")
  expect(done.uid).toBe("uid-1")
  expect(done.accountId).toBe("旅行者")
  expect(done.baseUrl).toBe("https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v2")
  expect(done.appKey).toBe("key1")
  expect(done.dpopPrivateJwk.kty).toBe("EC")
  // the page asked for a state; the code was polled; the tokens were posted
  // with a DPoP proof; the permission check named the gateway
  expect(calls.map((c) => c.url.pathname)).toEqual([
    "/v1/claw/auth/state", "/v1/claw/auth/code", "/v1/oauth2/tokens", "/v1/claw/client-permission-validate",
  ])
  expect(calls[2].headers.get("DPoP")).toMatch(/^eyJ0eXAiOiJkcG9wK2p3dCI/)
  expect(String(calls[2].init.body)).toContain("grant_type=authorization_code")
})

test("a 202 is waited out, then the code comes", async () => {
  let asked = 0
  serve({
    "/v1/claw/auth/state": () => ok({ state: "s1" }),
    "/v1/claw/auth/code": () => (asked++ < 2 ? new Response("", { status: 202 }) : ok({ code: "c1" })),
    "/v1/oauth2/tokens": () => ok(TOKENS),
    "/v1/claw/client-permission-validate": () => ok({
      model_info: { model_auth_info: { model_app_key: "k", model_app_secret: "s" }, model_api_url_base: "gw.example" },
    }),
  })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const step = await hooks.auth.methods[0].authorize()
  const done = await step.callback()
  expect(done.type).toBe("success")
}, 20000)

test("an account the cloud gives no gateway for is said so", async () => {
  serve({
    "/v1/claw/auth/state": () => ok({ state: "s1" }),
    "/v1/claw/auth/code": () => ok({ code: "c1" }),
    "/v1/oauth2/tokens": () => ok(TOKENS),
    "/v1/claw/client-permission-validate": () => ok({ subscription: { status: "PENDING" } }),
  })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const step = await hooks.auth.methods[0].authorize()
  const done = await step.callback()
  expect(done.type).toBe("failed")
  expect(done.error).toContain("no model gateway")
})

test("an imported gateway key is kept as an api auth", async () => {
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const m = hooks.auth.methods.find((x) => x.type === "api")
  const good = await m.authorize({ baseUrl: "https://gw.example/v2", key: "Basic a2V5OnNlY3JldA==" })
  expect(good).toEqual({ type: "success", key: "Basic a2V5OnNlY3JldA==", metadata: { baseUrl: "https://gw.example/v2" } })
  const bad = await m.authorize({ baseUrl: "gw.example", key: "" })
  expect(bad.type).toBe("failed")
})

test("a gateway key signs chats with itself, at the base it named", async () => {
  serve({ "/v2/chat/completions": () => new Response("data: [DONE]\n\n", { headers: { "content-type": "text/event-stream" } }) })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const opts = await hooks.auth.loader(async () => ({ type: "api", key: "Basic a2V5OnNlY3JldA==", metadata: { baseUrl: "https://gw.example/v2" } }))
  expect(opts.baseURL).toBe("https://gw.example/v2")
  const res = await opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: '{"messages":[]}' })
  expect(res.status).toBe(200)
})
