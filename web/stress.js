import http from "k6/http";
import { check, sleep } from "k6";

export const options = {
  stages: [
    { duration: "1m", target: 10 },
    { duration: "3m", target: 50 },
    { duration: "3m", target: 100 },
    { duration: "2m", target: 0 },
  ],
  thresholds: {
    http_req_failed: ["rate<0.02"], // menos de 2% de errores
    http_req_duration: ["p(95)<700"], // p95 bajo 700 ms
  },
};

const BASE = __ENV.BASE_URL; // p.ej. https://staging.tuapp.onrender.com
const paths = ["/", "/modsjg", "/reglas"];

export default function () {
  const path = paths[Math.floor(Math.random() * paths.length)];
  const res = http.get(`${BASE}${path}`);

  check(res, {
    "status 2xx/3xx": (r) => r.status >= 200 && r.status < 400,
    "dur <700ms": (r) => r.timings.duration < 700,
  });

  sleep(1);
}
