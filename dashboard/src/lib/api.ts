import type { FerroaMetrics } from './types';

const API_BASE = '/api';

export async function fetchMetrics(): Promise<FerroaMetrics> {
	const res = await fetch(`${API_BASE}/metrics`);
	if (!res.ok) throw new Error(`API error: ${res.status}`);
	return res.json();
}

// Generate realistic mock data when Ferroada backend is not running
function mockMetrics(): FerroaMetrics {
	const now = new Date();
	const base = Math.floor(now.getTime() / 60000) % 1000; // changes every minute, stays small

	const mockIps = [
		'39.144.12.88', '95.214.55.12', '185.220.101.34', '45.33.32.156',
		'112.85.42.88', '5.188.210.101', '177.71.244.60', '91.240.118.172',
		'123.125.71.38', '66.249.79.11', '141.98.11.95', '193.106.31.98',
		'203.208.60.175', '179.43.175.66', '46.161.9.18', '109.70.100.34',
		'220.181.108.91', '178.62.11.193', '86.105.18.116', '211.45.97.12',
	];
	const eventTypes = ['sqli', 'xss', 'path_traversal', 'rate_limit', 'sensitive_path', 'body_sqli'];
	const uris = [
		"/api/users?id=1' UNION SELECT--",
		'/search?q=<script>alert(1)</script>',
		'/../../etc/passwd',
		'/wp-login.php',
		'/.env',
		'/.git/config',
		"/api/auth?token=' OR 1=1--",
		'/admin/config.php',
		'/api/data?filter=<img onerror=alert(1)>',
		'/xmlrpc.php',
	];
	const details = [
		'SQL injection: UNION SELECT',
		'XSS: script tag detected',
		'Path traversal: ../',
		'Rate limit exceeded: 127 req/60s',
		'Sensitive path: /.env',
		'SQL injection in body: OR 1=1',
		'XSS in body: onerror handler',
		'Sensitive path: /.git/config',
		'Path traversal: encoded %2e%2e',
		'Rate limit exceeded: 203 req/60s',
	];

	const events = Array.from({ length: 24 }, (_, i) => {
		const seed = (base + i * 7) % mockIps.length;
		const eventSeed = (base + i * 3) % eventTypes.length;
		const t = new Date(now.getTime() - i * 12000);
		return {
			timestamp: t.toISOString().replace(/\.\d+Z/, 'Z'),
			event_type: eventTypes[eventSeed],
			client_ip: mockIps[(seed + i) % mockIps.length],
			uri: uris[(seed + i * 2) % uris.length],
			detail: details[(eventSeed + i) % details.length],
		};
	});

	const sqli = 47 + (base % 13);
	const xss = 23 + (base % 8);
	const pathT = 15 + (base % 6);
	const rateL = 89 + (base % 31);
	const sensitive = 34 + (base % 11);

	return {
		requests_total: 28473 + base * 3,
		blocked: {
			sqli,
			xss,
			path_traversal: pathT,
			rate_limit: rateL,
			sensitive_path: sensitive,
			body_sqli: 8 + (base % 5),
			body_xss: 4 + (base % 3),
			method: 2 + (base % 2),
			size_limit: 1,
			host: 3 + (base % 4),
		},
		https_redirect: 1247 + (base % 50),
		dlp: {
			cpf_masked: 12 + (base % 7),
			tokens_masked: 31 + (base % 15),
		},
		recent_events: events,
	};
}

export async function fetchMetricsWithFallback(): Promise<FerroaMetrics> {
	try {
		return await fetchMetrics();
	} catch {
		// Fallback to mock data when backend unavailable
		return mockMetrics();
	}
}
