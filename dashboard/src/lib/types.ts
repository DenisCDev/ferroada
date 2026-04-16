export interface BlockedMetrics {
	sqli: number;
	xss: number;
	path_traversal: number;
	rate_limit: number;
	sensitive_path: number;
	body_sqli: number;
	body_xss: number;
	method: number;
	size_limit: number;
	host: number;
}

export interface DlpMetrics {
	cpf_masked: number;
	tokens_masked: number;
}

export interface SecurityEvent {
	timestamp: string;
	event_type: string;
	client_ip: string;
	uri: string;
	detail: string;
}

export interface FerroaMetrics {
	requests_total: number;
	blocked: BlockedMetrics;
	https_redirect: number;
	dlp: DlpMetrics;
	recent_events: SecurityEvent[];
}

export interface GeoPoint {
	lat: number;
	lng: number;
	label: string;
	count: number;
}

export interface TimelinePoint {
	time: Date;
	blocked: number;
	requests: number;
}

export type AttackCategory = {
	key: string;
	label: string;
	count: number;
	color: string;
};
