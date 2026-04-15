import type { FerroaMetrics, SecurityEvent } from '~/types';

export async function fetchMetrics(): Promise<FerroaMetrics> {
  const res = await fetch('/api/metrics');
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export function mockMetrics(): FerroaMetrics {
  const base = Math.floor(Date.now() / 60000) % 1000;

  const attackUris = [
    "/login?user=admin'--",
    '/api/users?q=<script>alert(1)</script>',
    '/../../../../etc/passwd',
    '/wp-admin/install.php',
    '/.env',
    '/api/data?id=1 OR 1=1',
    '/search?q=<img onerror=alert(1) src=x>',
    '/api/config/../../../etc/shadow',
    '/actuator/health',
    '/.git/config',
    "/graphql?query={__schema{types{name}}}",
    '/api/login',
    '/admin/dashboard',
    '/api/v1/tokens',
    '/xmlrpc.php',
    '/api/export?fmt=csv&q=SELECT+*+FROM+users',
    '/assets/<svg onload=fetch("//evil.com")>',
    '/../../../var/log/auth.log',
    '/server-status',
    '/.aws/credentials',
    "/api/auth?pass=' UNION SELECT *--",
    '/comments?body=<iframe src=//evil.com>',
    '/static/../../proc/self/environ',
    '/phpmyadmin/index.php',
  ];

  const attackIps = [
    '45.33.32.156', '185.220.101.34', '112.85.42.88', '191.96.249.12',
    '103.145.13.22', '77.247.181.165', '202.14.109.3', '154.16.93.40',
    '61.177.172.55', '178.128.88.91', '125.64.94.12', '186.233.187.1',
    '58.218.92.37', '141.98.11.108', '196.52.43.88', '217.138.222.19',
    '180.101.88.196', '189.6.45.201', '110.34.232.8', '95.214.55.43',
    '39.144.16.88', '176.111.174.22', '200.58.123.4', '150.107.2.15',
  ];

  const eventTypes = [
    'sqli', 'xss', 'path_traversal', 'rate_limit', 'sensitive_path',
    'body_sqli', 'body_xss', 'method', 'size_limit', 'host',
    'crlf', 'smuggling', 'jndi', 'bad_bot',
    'behavioral_throttle', 'behavioral_block',
  ];

  // Weight IPs so top origins have varied counts (not all 1)
  const weightedIps = [
    ...Array(7).fill(attackIps[0]),   // Beijing — 7 hits
    ...Array(5).fill(attackIps[1]),   // Moscow — 5 hits
    ...Array(4).fill(attackIps[2]),   // Chengdu — 4 hits
    ...Array(3).fill(attackIps[3]),   // Porto Alegre — 3 hits
    ...Array(2).fill(attackIps[4]),   // Singapore — 2 hits
    attackIps[5], attackIps[6], attackIps[7], // 1 hit each
  ];

  const recent_events: SecurityEvent[] = Array.from({ length: 24 }, (_, i) => {
    const ts = new Date(Date.now() - (23 - i) * 60000);
    const evtType = eventTypes[i % eventTypes.length];
    return {
      timestamp: ts.toISOString(),
      event_type: evtType,
      client_ip: weightedIps[i % weightedIps.length],
      uri: attackUris[i % attackUris.length],
      detail: `Blocked ${evtType.replace(/_/g, ' ')} attempt`,
    };
  });

  return {
    requests_total: 28000 + base * 3 + Math.floor(Math.random() * 1000),
    blocked: {
      sqli: 80 + (base % 40),
      xss: 55 + (base % 30),
      path_traversal: 40 + (base % 25),
      rate_limit: 90 + (base % 30),
      sensitive_path: 35 + (base % 20),
      body_sqli: 25 + (base % 15),
      body_xss: 18 + (base % 12),
      method: 5 + (base % 10),
      size_limit: 8 + (base % 10),
      host: 12 + (base % 10),
      crlf: 3 + (base % 5),
      smuggling: 1 + (base % 3),
      jndi: 2 + (base % 4),
      bad_bot: 15 + (base % 20),
      behavioral_throttle: 8 + (base % 12),
      behavioral_block: 2 + (base % 5),
    },
    https_redirect: 1200 + base * 2,
    dlp: {
      cpf_masked: 45 + (base % 30),
      tokens_masked: 22 + (base % 15),
    },
    recent_events,
  };
}

export async function fetchMetricsWithFallback(): Promise<FerroaMetrics> {
  try {
    return await fetchMetrics();
  } catch {
    console.warn('[Ferroada] API unavailable, using mock data');
    return mockMetrics();
  }
}
