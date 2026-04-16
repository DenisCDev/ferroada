export interface FerroaMetrics {
  requests_total: number;
  blocked: Record<string, number>;
  https_redirect: number;
  dlp: { cpf_masked: number; tokens_masked: number };
  recent_events: SecurityEvent[];
}

export interface SecurityEvent {
  timestamp: string;
  event_type: string;
  client_ip: string;
  uri: string;
  detail: string;
}

export interface GeoPoint {
  lat: number;
  lng: number;
  label: string;
  count: number;
}

export interface AttackCategory {
  key: string;
  label: string;
  count: number;
}

export interface TimelinePoint {
  time: Date;
  blocked: number;
}
