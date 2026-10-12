// The two Huawei Cloud signatures, as officeace2api's quota.mjs makes them
// (its tools test them against the live signer): the control plane's
// SDK-HMAC-SHA256 and the subscription API's V11-HMAC-SHA256, whose key is
// derived through the region scope.
import { test, expect } from "bun:test"
import { _internal } from "./index.mjs"

const { signV4, signV11 } = _internal

const cred = { accessKey: "AKTEST", secretKey: "SKTEST", securityToken: "tok", projectId: "proj" }

test("signV4 names its parts and signs the canonical request", () => {
  const url = "https://agentarts.cn-southwest-2.myhuaweicloud.com/v1/claw/client-permission-validate"
  const headers = signV4({
    method: "GET",
    url,
    credential: cred,
    contentType: "application/json;charset=utf8",
    sdkDateOverride: "20261012T000000Z",
  })
  expect(headers["X-Sdk-Date"]).toBe("20261012T000000Z")
  expect(headers["X-Security-Token"]).toBe("tok")
  expect(headers["X-Project-ID"]).toBe("proj")
  expect(headers.Host).toBe(new URL(url).host)
  expect(headers["Content-Type"]).toBe("application/json;charset=utf8")
  const m = /^SDK-HMAC-SHA256 Access=(\w+), SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(headers.Authorization)
  expect(m[1]).toBe("AKTEST")
  // every header the signer set is signed, by name, sorted
  expect(m[2].split(";")).toEqual(["content-type", "host", "x-project-id", "x-sdk-date", "x-security-token"])
  expect(m[3]).toMatch(/^[0-9a-f]{64}$/)
})

test("signV11 derives its key through the region scope", () => {
  const url = "https://modelgw-0004.officeace.cn-southwest-2.huaweicloud-agentarts.com/v1/subscription"
  const headers = signV11({
    method: "GET",
    url,
    credential: cred,
    headers: { "x-subscription-type": "v2" },
    sdkDateOverride: "20261012T000000Z",
  })
  expect(headers["x-subscription-type"]).toBe("v2")
  const m = /^V11-HMAC-SHA256 Credential=(\w+)\/([^,]+), SignedHeaders=([^,]+), Signature=([0-9a-f]{64})$/.exec(headers.Authorization)
  expect(m[1]).toBe("AKTEST")
  expect(m[2]).toBe("20261012/cn-southwest-2/apic")
  expect(m[3].split(";")).toEqual(["host", "x-project-id", "x-sdk-date", "x-security-token", "x-subscription-type"])
  expect(m[4]).toMatch(/^[0-9a-f]{64}$/)
})

// the same input gives the same signature, whatever the case the caller
// spelled the headers in
test("signing is case-insensitive in the headers it receives", () => {
  const url = "https://gw.example/v1/subscription"
  const a = signV11({ method: "GET", url, credential: cred, headers: { "X-Subscription-Type": "v2" }, sdkDateOverride: "20261012T000000Z" })
  const b = signV11({ method: "GET", url, credential: cred, headers: { "x-subscription-type": "v2" }, sdkDateOverride: "20261012T000000Z" })
  expect(a.Authorization).toBe(b.Authorization)
})

test("a body is signed by its hash", () => {
  const url = "https://gw.example/v1/subscription/bonus/claim"
  const once = signV11({ method: "POST", url, credential: cred, bodyText: "{}", contentType: "application/json;charset=utf8", sdkDateOverride: "20261012T000000Z" })
  const twice = signV11({ method: "POST", url, credential: cred, bodyText: "{}", contentType: "application/json;charset=utf8", sdkDateOverride: "20261012T000000Z" })
  const other = signV11({ method: "POST", url, credential: cred, bodyText: '{"a":1}', contentType: "application/json;charset=utf8", sdkDateOverride: "20261012T000000Z" })
  expect(once.Authorization).toBe(twice.Authorization)
  expect(once.Authorization).not.toBe(other.Authorization)
})
