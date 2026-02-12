import http from "k6/http";
import { check, group, sleep, fail } from "k6";
import { Counter } from "k6/metrics";

const http_401 = new Counter("http_401");
const http_5xx = new Counter("http_5xx");

function countStatus(res, endpoint) {
  if (res.status === 401) http_401.add(1, { endpoint });
  if (res.status >= 500) http_5xx.add(1, { endpoint });
}

const BASE_URL = __ENV.BASE_URL;
const LOGIN = __ENV.LOGIN;
const PASSWORD = __ENV.PASSWORD;
const STRICT = (__ENV.STRICT || "0") === "1";

export const options = {
  scenarios: {
    sso_flow: {
      executor: "ramping-vus",
      startVUs: 0,
      stages: [
        { duration: "15s", target: 20 },
        { duration: "30s", target: 50 },
        { duration: "30s", target: 100 },
        { duration: "15s", target: 0 },
      ],
      gracefulRampDown: "10s",
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.02"],
    http_req_duration: ["p(95)<2000"],
  },
};

function jsonHeaders(extra = {}) {
  return { "Content-Type": "application/json", ...extra };
}
function bearer(token) {
  return { Authorization: `Bearer ${token}` };
}
function must(ok, msg) {
  if (!ok && STRICT) fail(msg);
}

export default function () {
  const jar = http.cookieJar();

  let accessToken = "";

  group("login", () => {
    const url = `${BASE_URL}/auth/login`;
    const payload = JSON.stringify({ login: LOGIN, password: PASSWORD });

    const res = http.post(url, payload, {
      headers: jsonHeaders(),
      tags: { endpoint: "login" },
    });

    const ok = check(res, {
      "login status 200": (r) => r.status === 200,
      "login has access_token": (r) => {
        try {
          const j = r.json();
          return typeof j?.access_token === "string" && j.access_token.length > 0;
        } catch {
          return false;
        }
      },
    });

    must(ok, `Login failed: status=${res.status}`);
    accessToken = res.json("access_token");

    const cookies = jar.cookiesForURL(BASE_URL);
    must(!!cookies["refresh_token"] && cookies["refresh_token"].length > 0, "No refresh_token cookie after login");
    countStatus(res,"login")
  });


  group("validate", () => {
    const url = `${BASE_URL}/auth/validate`;
    const res = http.get(url, {
      headers: jsonHeaders(bearer(accessToken)),
      tags: { endpoint: "validate" },
    });

    const ok = check(res, { "validate status 200": (r) => r.status === 200 });
    must(ok, `Validate failed: status=${res.status}`);
    countStatus(res,"validate")
  });


  group("authenticate", () => {
    const url = `${BASE_URL}/auth/authenticate`;
    const res = http.get(url, {
      headers: jsonHeaders(bearer(accessToken)),
      tags: { endpoint: "authenticate" },
    });

    const ok = check(res, { "authenticate status 200": (r) => r.status === 200 });
    must(ok, `Authenticate failed: status=${res.status}`);
    countStatus(res,"authenticate")
  });


  group("refresh", () => {
    const url = `${BASE_URL}/auth/refresh`;
    const res = http.post(url, null, {
      headers: jsonHeaders(),
      tags: { endpoint: "refresh" },
    });

    const ok = check(res, {
      "refresh status 200": (r) => r.status === 200,
      "refresh has access_token": (r) => {
        try {
          const j = r.json();
          return typeof j?.access_token === "string" && j.access_token.length > 0;
        } catch {
          return false;
        }
      },
    });

    must(ok, `Refresh failed: status=${res.status}`);
    accessToken = res.json("access_token");
    countStatus(res,"refresh")
  });


  group("validate_after_refresh", () => {
    const url = `${BASE_URL}/auth/validate`;
    const res = http.get(url, {
      headers: jsonHeaders(bearer(accessToken)),
      tags: { endpoint: "validate2" },
    });

    const ok = check(res, { "validate2 status 200": (r) => r.status === 200 });
    must(ok, `Validate2 failed: status=${res.status}`);
    countStatus(res,"validate_after_refresh")
  });


  group("logout", () => {
    const url = `${BASE_URL}/auth/logout`;
    const res = http.post(url, null, {
      headers: jsonHeaders(),
      tags: { endpoint: "logout" },
    });

    const ok = check(res, { "logout status 200": (r) => r.status === 200 });
    must(ok, `Logout failed: status=${res.status}`);
    countStatus(res,"logout")
  });

  sleep(0.1);
}
