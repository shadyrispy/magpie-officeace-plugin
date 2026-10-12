// The chats: the gateway takes OpenAI's shape on the account's Basic key;
// the body is mended (the thinking budget, glm-5.3's refused params), an
// agent's one-piece answer is folded back from the stream, refusals say
// the sign-in is kept.
import { test, expect, afterEach } from "bun:test"
import { OfficeAceAuthPlugin, _internal } from "./index.mjs"

const real = globalThis.fetch
afterEach(() => (globalThis.fetch = real))

const ok = (data) => new Response(JSON.stringify(data), { status: 200 })

function serve(routes) {
  const calls = []
  globalThis.fetch = async (url, init) => {
    const u = new URL(String(url))
    calls.push({ url: u, init, headers: new Headers(init?.headers) })
    const r = routes[u.pathname]
    return r ? r(init) : new Response("", { status: 404 })
  }
  return calls
}

const auth = (over = {}) => ({
  type: "oauth", access: "ak", secret: "sk", securityToken: "st", projectId: "p",
  expires: Date.now() + 20 * 3600 * 1000, refresh: "r", refreshExpiresAt: Date.now() + 30 * 24 * 3600 * 1000,
  uid: "u1", baseUrl: "https://gw.example/v2", appKey: "key1", appSecret: "sec1",
  ...over,
})

const hooksOf = async (a) => (await OfficeAceAuthPlugin({ client: {} })).auth.loader(async () => a)

const chat = async (opts, body) => opts.fetch("https://gw.example/v2/chat/completions", { method: "POST", body: JSON.stringify(body) })

const sse = (deltas) =>
  new Response(deltas.map((d) => `data: ${JSON.stringify(d)}\n\n`).join("") + "data: [DONE]\n\n", {
    headers: { "content-type": "text/event-stream" },
  })

test("a streamed chat goes through on the Basic key", async () => {
  const calls = serve({ "/v2/chat/completions": () => sse([{ choices: [{ delta: { content: "hi" } }] }]) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "glm-5.2", messages: [{ role: "user", content: "hello" }], stream: true })
  expect(res.status).toBe(200)
  const c = calls[0]
  expect(c.url.href).toBe("https://gw.example/v2/chat/completions")
  expect(c.headers.get("authorization")).toBe("Basic " + Buffer.from("key1:sec1").toString("base64"))
  const sent = JSON.parse(c.init.body)
  expect(sent.stream).toBe(true)
  expect(sent.stream_options).toEqual({ include_usage: true })
})

test("a one-piece answer is folded back from the stream", async () => {
  serve({ "/v2/chat/completions": () => sse([
    { id: "c1", created: 1, model: "deepseek-v4.1-flash", choices: [{ delta: { role: "assistant", content: "he" } }] },
    { choices: [{ delta: { content: "llo" } }] },
    { choices: [{ delta: { reasoning_content: "th" } }] },
    { choices: [{ delta: { reasoning_content: "ink" } }] },
    { choices: [{ delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 } },
  ]) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "hello" }] })
  expect(res.headers.get("content-type")).toContain("application/json")
  const v = await res.json()
  expect(v.id).toBe("c1")
  expect(v.model).toBe("deepseek-v4.1-flash")
  expect(v.choices[0].message.content).toBe("hello")
  expect(v.choices[0].message.reasoning_content).toBe("think")
  expect(v.choices[0].finish_reason).toBe("stop")
  expect(v.usage.total_tokens).toBe(8)
})

test("tool calls gather their pieces", async () => {
  serve({ "/v2/chat/completions": () => sse([
    { choices: [{ delta: { tool_calls: [{ index: 0, id: "t1", type: "function", function: { name: "get_weather", arguments: '{"ci' } }] } }] },
    { choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'ty":"北京"}' } }] } }] },
    { choices: [{ delta: {}, finish_reason: "tool_calls" }] },
  ]) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "deepseek-v4.1-flash", messages: [{ role: "user", content: "weather" }] })
  const v = await res.json()
  const [tc] = v.choices[0].message.tool_calls
  expect(tc.id).toBe("t1")
  expect(tc.function.name).toBe("get_weather")
  expect(tc.function.arguments).toBe('{"city":"北京"}')
  expect(v.choices[0].finish_reason).toBe("tool_calls")
})

test("the max_tokens budget is bumped for the thinking, a tiny one is kept", async () => {
  const calls = serve({ "/v2/chat/completions": () => sse([{ choices: [{ delta: { content: "ok" } }] }]) })
  const opts = await hooksOf(auth())
  await chat(opts, { model: "deepseek-v4.1-flash", messages: [], max_tokens: 64 })
  expect(JSON.parse(calls[0].init.body).max_tokens).toBe(64 + _internal.THINKING_ALLOWANCE)
  await chat(opts, { model: "deepseek-v4.1-flash", messages: [], max_tokens: 1 })
  expect(JSON.parse(calls[1].init.body).max_tokens).toBe(1)
  await chat(opts, { model: "deepseek-v4.1-flash", messages: [] })
  expect(JSON.parse(calls[2].init.body).max_tokens).toBeUndefined() // not ours to invent
})

test("glm-5.3's refused thinking params are stripped, other models' kept", async () => {
  const calls = serve({ "/v2/chat/completions": () => sse([{ choices: [{ delta: { content: "ok" } }] }]) })
  const opts = await hooksOf(auth())
  const body = { messages: [], thinking: { type: "disabled" }, enable_thinking: false, stream_options: { include_usage: true } }
  await chat(opts, { model: "glm-5.3", ...body })
  const sent = JSON.parse(calls[0].init.body)
  expect("thinking" in sent).toBe(false)
  expect("enable_thinking" in sent).toBe(false)
  await chat(opts, { model: "deepseek-v4.1-flash", ...body })
  const kept = JSON.parse(calls[1].init.body)
  expect(kept.thinking).toEqual({ type: "disabled" })
})

test("a refusal for spent credits says what to do, the sign-in kept", async () => {
  serve({ "/v2/chat/completions": () => new Response(JSON.stringify({ error_msg: "Insufficient points" }), { status: 403 }) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "glm-5.2", messages: [] })
  expect(res.status).toBe(403)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
  const v = await res.json()
  expect(v.error.type).toBe("insufficient_quota")
  expect(v.error.message).toContain(_internal.EXHAUSTED_HINT)
})

test("any other refusal goes through as it came, the sign-in kept", async () => {
  serve({ "/v2/chat/completions": () => new Response('{"error":{"message":"ModelArts.81009 Invalid model"}}', { status: 400 }) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "no-such-model", messages: [] })
  expect(res.status).toBe(400)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
  expect(await res.text()).toBe('{"error":{"message":"ModelArts.81009 Invalid model"}}')
})

test("a 401 keeps the account too: the Basic key never ends", async () => {
  serve({ "/v2/chat/completions": () => new Response("APIG.1002", { status: 401 }) })
  const opts = await hooksOf(auth())
  const res = await chat(opts, { model: "glm-5.2", messages: [] })
  expect(res.status).toBe(401)
  expect(res.headers.get("X-Magpie-Sign-In")).toBe("kept")
})

// ---- the models ---------------------------------------------------------------

test("the static list stands until the gateway answers", async () => {
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const cfg = {}
  await hooks.config(cfg)
  expect(Object.keys(cfg.provider.officeace.models)).toContain("glm-5.2")
  expect(Object.keys(cfg.provider.officeace.models)).toContain("deepseek-v4.1-flash")
  // an account that isn't signed in leaves the list as the provider had it
  const p = { id: "officeace", models: { seeded: { name: "Seeded" } } }
  const out = await hooks.provider.models(p, { auth: null })
  expect(Object.keys(out)).toEqual(["seeded"])
})

test("the account's own list, with the registry's context where known", async () => {
  serve({ "/v2/models": () => ok({ data: [{ id: "glm-5.2" }, { id: "brand-new-model", name: "Brand New" }] }) })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const out = await hooks.provider.models({ id: "officeace", models: {} }, { auth: auth() })
  expect(out["glm-5.2"].limit.context).toBe(198000)
  expect(out["glm-5.2"].name).toBe("GLM-5.2")
  expect(out["brand-new-model"].name).toBe("Brand New")
  expect(out["brand-new-model"].api.url).toBe("https://gw.example/v2")
})

test("a gateway that doesn't answer leaves the list as it was", async () => {
  serve({ "/v2/models": () => new Response("", { status: 500 }) })
  const hooks = await OfficeAceAuthPlugin({ client: {} })
  const p = { id: "officeace", models: { seeded: { name: "Seeded" } } }
  const out = await hooks.provider.models(p, { auth: auth() })
  expect(Object.keys(out)).toEqual(["seeded"])
})
