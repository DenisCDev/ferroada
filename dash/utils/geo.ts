import type { SecurityEvent, GeoPoint } from '~/types';

interface GeoLocation {
  lat: number;
  lng: number;
  label: string;
}

const octetMap: Record<number, GeoLocation> = {
  // Asia
  39:  { lat: 39.9042, lng: 116.4074, label: 'Beijing' },
  40:  { lat: 31.2304, lng: 121.4737, label: 'Shanghai' },
  58:  { lat: 35.6762, lng: 139.6503, label: 'Tokyo' },
  59:  { lat: 37.5665, lng: 126.9780, label: 'Seoul' },
  61:  { lat: 22.3193, lng: 114.1694, label: 'Hong Kong' },
  112: { lat: 30.5728, lng: 104.0668, label: 'Chengdu' },
  113: { lat: 23.1291, lng: 113.2644, label: 'Guangzhou' },
  114: { lat: 22.5431, lng: 114.0579, label: 'Shenzhen' },
  115: { lat: 39.9042, lng: 116.4074, label: 'Beijing' },
  116: { lat: 31.2304, lng: 121.4737, label: 'Shanghai' },
  117: { lat: 34.3416, lng: 108.9398, label: "Xi'an" },
  118: { lat: 32.0603, lng: 118.7969, label: 'Nanjing' },
  119: { lat: 36.0671, lng: 120.3826, label: 'Qingdao' },
  120: { lat: 30.2741, lng: 120.1551, label: 'Hangzhou' },
  121: { lat: 25.0330, lng: 121.5654, label: 'Taipei' },
  122: { lat: 38.9140, lng: 121.6147, label: 'Dalian' },
  123: { lat: 43.8171, lng: 125.3235, label: 'Changchun' },
  124: { lat: 41.8057, lng: 123.4315, label: 'Shenyang' },
  125: { lat: 45.7500, lng: 126.6500, label: 'Harbin' },
  175: { lat: 19.0760, lng: 72.8777, label: 'Mumbai' },
  180: { lat: 28.6139, lng: 77.2090, label: 'New Delhi' },
  202: { lat: 13.7563, lng: 100.5018, label: 'Bangkok' },
  203: { lat: -6.2088, lng: 106.8456, label: 'Jakarta' },
  204: { lat: 14.5995, lng: 120.9842, label: 'Manila' },
  205: { lat: 1.3521, lng: 103.8198, label: 'Singapore' },
  206: { lat: 21.0278, lng: 105.8342, label: 'Hanoi' },
  207: { lat: 35.6762, lng: 139.6503, label: 'Tokyo' },
  208: { lat: 37.5665, lng: 126.9780, label: 'Seoul' },
  209: { lat: 22.3193, lng: 114.1694, label: 'Hong Kong' },
  210: { lat: 39.9042, lng: 116.4074, label: 'Beijing' },
  211: { lat: 37.5665, lng: 126.9780, label: 'Seoul' },
  218: { lat: 35.6762, lng: 139.6503, label: 'Tokyo' },
  219: { lat: 37.5665, lng: 126.9780, label: 'Seoul' },
  220: { lat: 31.2304, lng: 121.4737, label: 'Shanghai' },
  221: { lat: 39.9042, lng: 116.4074, label: 'Beijing' },
  222: { lat: 23.1291, lng: 113.2644, label: 'Guangzhou' },
  223: { lat: 30.5728, lng: 104.0668, label: 'Chengdu' },

  // Europe
  77:  { lat: 52.5200, lng: 13.4050, label: 'Berlin' },
  78:  { lat: 48.8566, lng: 2.3522, label: 'Paris' },
  79:  { lat: 40.4168, lng: -3.7038, label: 'Madrid' },
  80:  { lat: 41.9028, lng: 12.4964, label: 'Rome' },
  81:  { lat: 48.2082, lng: 16.3738, label: 'Vienna' },
  82:  { lat: 50.0755, lng: 14.4378, label: 'Prague' },
  83:  { lat: 47.4979, lng: 19.0402, label: 'Budapest' },
  84:  { lat: 44.4268, lng: 26.1025, label: 'Bucharest' },
  85:  { lat: 59.3293, lng: 18.0686, label: 'Stockholm' },
  86:  { lat: 60.1699, lng: 24.9384, label: 'Helsinki' },
  87:  { lat: 59.9139, lng: 10.7522, label: 'Oslo' },
  88:  { lat: 55.6761, lng: 12.5683, label: 'Copenhagen' },
  89:  { lat: 52.3676, lng: 4.9041, label: 'Amsterdam' },
  90:  { lat: 50.8503, lng: 4.3517, label: 'Brussels' },
  91:  { lat: 46.2044, lng: 6.1432, label: 'Geneva' },
  92:  { lat: 38.7223, lng: -9.1393, label: 'Lisbon' },
  93:  { lat: 53.3498, lng: -6.2603, label: 'Dublin' },
  94:  { lat: 55.7558, lng: 37.6173, label: 'Moscow' },
  95:  { lat: 59.9311, lng: 30.3609, label: 'St. Petersburg' },
  141: { lat: 50.4501, lng: 30.5234, label: 'Kyiv' },
  176: { lat: 52.2297, lng: 21.0122, label: 'Warsaw' },
  177: { lat: -23.5505, lng: -46.6333, label: 'São Paulo' },
  178: { lat: 51.5074, lng: -0.1278, label: 'London' },
  179: { lat: 48.8566, lng: 2.3522, label: 'Paris' },
  185: { lat: 55.7558, lng: 37.6173, label: 'Moscow' },
  188: { lat: 55.7558, lng: 37.6173, label: 'Moscow' },
  193: { lat: 52.5200, lng: 13.4050, label: 'Berlin' },
  194: { lat: 48.8566, lng: 2.3522, label: 'Paris' },
  195: { lat: 41.9028, lng: 12.4964, label: 'Rome' },
  212: { lat: 41.0082, lng: 28.9784, label: 'Istanbul' },
  213: { lat: 40.4168, lng: -3.7038, label: 'Madrid' },
  214: { lat: 52.5200, lng: 13.4050, label: 'Berlin' },
  215: { lat: 51.5074, lng: -0.1278, label: 'London' },
  216: { lat: 45.4642, lng: 9.1900, label: 'Milan' },
  217: { lat: 48.2082, lng: 16.3738, label: 'Vienna' },

  // South America
  186: { lat: -22.9068, lng: -43.1729, label: 'Rio de Janeiro' },
  187: { lat: -15.7975, lng: -47.8919, label: 'Brasília' },
  189: { lat: -19.9167, lng: -43.9345, label: 'Belo Horizonte' },
  191: { lat: -30.0346, lng: -51.2177, label: 'Porto Alegre' },
  200: { lat: -34.6037, lng: -58.3816, label: 'Buenos Aires' },
  201: { lat: -33.4489, lng: -70.6693, label: 'Santiago' },

  // Africa
  41:  { lat: 30.0444, lng: 31.2357, label: 'Cairo' },
  105: { lat: 33.5731, lng: -7.5898, label: 'Casablanca' },
  154: { lat: 6.5244, lng: 3.3792, label: 'Lagos' },
  196: { lat: -33.9249, lng: 18.4241, label: 'Cape Town' },
  197: { lat: -26.2041, lng: 28.0473, label: 'Johannesburg' },

  // Oceania
  103: { lat: 1.3521, lng: 103.8198, label: 'Singapore' },
  110: { lat: -33.8688, lng: 151.2093, label: 'Sydney' },
  150: { lat: -37.8136, lng: 144.9631, label: 'Melbourne' },
};

const usEuCities: GeoLocation[] = [
  { lat: 40.7128, lng: -74.0060, label: 'New York' },
  { lat: 34.0522, lng: -118.2437, label: 'Los Angeles' },
  { lat: 41.8781, lng: -87.6298, label: 'Chicago' },
  { lat: 29.7604, lng: -95.3698, label: 'Houston' },
  { lat: 33.4484, lng: -112.0740, label: 'Phoenix' },
  { lat: 47.6062, lng: -122.3321, label: 'Seattle' },
  { lat: 37.7749, lng: -122.4194, label: 'San Francisco' },
  { lat: 25.7617, lng: -80.1918, label: 'Miami' },
  { lat: 42.3601, lng: -71.0589, label: 'Boston' },
  { lat: 38.9072, lng: -77.0369, label: 'Washington DC' },
  { lat: 39.7392, lng: -104.9903, label: 'Denver' },
  { lat: 36.1627, lng: -86.7816, label: 'Nashville' },
];

function defaultLocation(): GeoLocation {
  return { lat: 51.5074, lng: -0.1278, label: 'London' };
}

export function ipToGeo(ip: string): GeoLocation {
  const firstOctet = parseInt(ip.split('.')[0], 10);
  if (isNaN(firstOctet)) return defaultLocation();

  // Direct lookup in octet map
  if (octetMap[firstOctet]) {
    return octetMap[firstOctet];
  }

  // US/EU ranges: 1-38, 42-57, 62-76
  if (
    (firstOctet >= 1 && firstOctet <= 38) ||
    (firstOctet >= 42 && firstOctet <= 57) ||
    (firstOctet >= 62 && firstOctet <= 76)
  ) {
    return usEuCities[firstOctet % usEuCities.length];
  }

  return defaultLocation();
}

export function aggregateGeoPoints(events: SecurityEvent[]): GeoPoint[] {
  const map = new Map<string, GeoPoint>();

  for (const event of events) {
    const geo = ipToGeo(event.client_ip);
    const key = `${geo.lat},${geo.lng}`;

    if (map.has(key)) {
      map.get(key)!.count++;
    } else {
      map.set(key, {
        lat: geo.lat,
        lng: geo.lng,
        label: geo.label,
        count: 1,
      });
    }
  }

  return Array.from(map.values()).sort((a, b) => b.count - a.count);
}
