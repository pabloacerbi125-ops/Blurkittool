import http from "k6/http";
import { check, sleep, group } from "k6";

export const options = {
  stages: [
    { duration: "30s", target: 20 },
    { duration: "1m", target: 80 },
    { duration: "1m", target: 160 },
    { duration: "30s", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.05"], // permitimos hasta 5% porque habrá 429
    http_req_duration: ["p(95)<900"],
    "checks{type:429}": ["rate>0.01"], // esperamos ver 429 bajo presión
  },
};

const BASE = __ENV.BASE_URL;
const paths = ["/login", "/search?q=abc", "/paste", "/"];

export default function () {
  group("bot-burst", () => {
    for (let i = 0; i < 5; i++) {
      const path = paths[Math.floor(Math.random() * paths.length)];
      const res = http.get(`${BASE}${path}`);

      check(res, {
        "429 esperado": (r) => r.status === 429,
        "ok o 429": (r) => (r.status >= 200 && r.status < 400) || r.status === 429,
      }, { type: res.status === 429 ? "429" : "normal" });
    }
  });

  sleep(0.2); // alta frecuencia de peticiones tipo bot
}
