import type { GeoPoint } from './types';

// IP first-octet to approximate geolocation
// Based on IANA regional allocation blocks
// In production, use MaxMind GeoLite2 in the Rust backend for accurate data
const REGION_MAP: Record<number, { lat: number; lng: number; label: string }> = {
	// APNIC (Asia-Pacific)
	1: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	14: { lat: 22.32, lng: 114.17, label: 'Hong Kong' },
	27: { lat: 30.04, lng: 31.24, label: 'Cairo, EG' },
	36: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	39: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	42: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	43: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	49: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	58: { lat: 31.23, lng: 121.47, label: 'Shanghai, CN' },
	59: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	60: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	61: { lat: -33.87, lng: 151.21, label: 'Sydney, AU' },
	101: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	103: { lat: 19.08, lng: 72.88, label: 'Mumbai, IN' },
	106: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	110: { lat: 31.23, lng: 121.47, label: 'Shanghai, CN' },
	111: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	112: { lat: 23.13, lng: 113.26, label: 'Guangzhou, CN' },
	113: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	114: { lat: 22.32, lng: 114.17, label: 'Hong Kong' },
	115: { lat: -6.21, lng: 106.85, label: 'Jakarta, ID' },
	116: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	117: { lat: 36.07, lng: 120.38, label: 'Qingdao, CN' },
	118: { lat: 31.23, lng: 121.47, label: 'Shanghai, CN' },
	119: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	120: { lat: 25.03, lng: 121.57, label: 'Taipei, TW' },
	121: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	122: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	123: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	124: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	125: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	// RIPE (Europe/Middle East)
	2: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	5: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	31: { lat: 52.52, lng: 13.41, label: 'Berlin, DE' },
	37: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	46: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	62: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	77: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	78: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	79: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	80: { lat: 52.37, lng: 4.90, label: 'Amsterdam, NL' },
	81: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	82: { lat: 50.11, lng: 8.68, label: 'Frankfurt, DE' },
	83: { lat: 52.52, lng: 13.41, label: 'Berlin, DE' },
	84: { lat: 40.42, lng: -3.70, label: 'Madrid, ES' },
	85: { lat: 59.33, lng: 18.07, label: 'Stockholm, SE' },
	86: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	87: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	88: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	89: { lat: 52.37, lng: 4.90, label: 'Amsterdam, NL' },
	90: { lat: 41.01, lng: 28.98, label: 'Istanbul, TR' },
	91: { lat: 50.08, lng: 14.44, label: 'Prague, CZ' },
	92: { lat: 59.33, lng: 18.07, label: 'Stockholm, SE' },
	93: { lat: 48.21, lng: 16.37, label: 'Vienna, AT' },
	94: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	95: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	109: { lat: 44.43, lng: 26.10, label: 'Bucharest, RO' },
	141: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	145: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	146: { lat: 44.43, lng: 26.10, label: 'Bucharest, RO' },
	151: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	176: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	178: { lat: 52.37, lng: 4.90, label: 'Amsterdam, NL' },
	185: { lat: 50.11, lng: 8.68, label: 'Frankfurt, DE' },
	188: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	193: { lat: 52.37, lng: 4.90, label: 'Amsterdam, NL' },
	194: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	195: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	212: { lat: 41.01, lng: 28.98, label: 'Istanbul, TR' },
	213: { lat: 40.42, lng: -3.70, label: 'Madrid, ES' },
	217: { lat: 52.52, lng: 13.41, label: 'Berlin, DE' },
	// ARIN (North America)
	3: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	4: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	6: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	7: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	8: { lat: 37.39, lng: -122.08, label: 'Mountain View, US' },
	9: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	10: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	11: { lat: 38.90, lng: -77.04, label: 'Washington, US' },
	12: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	13: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	15: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	16: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	17: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	18: { lat: 42.36, lng: -71.06, label: 'Boston, US' },
	19: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	20: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	23: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	24: { lat: 45.50, lng: -73.57, label: 'Montreal, CA' },
	25: { lat: 51.05, lng: -114.07, label: 'Calgary, CA' },
	34: { lat: 32.78, lng: -96.80, label: 'Dallas, US' },
	35: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	38: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	40: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	44: { lat: 43.65, lng: -79.38, label: 'Toronto, CA' },
	45: { lat: 43.65, lng: -79.38, label: 'Toronto, CA' },
	47: { lat: 45.50, lng: -73.57, label: 'Montreal, CA' },
	48: { lat: 32.78, lng: -96.80, label: 'Dallas, US' },
	50: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	52: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	54: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	55: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	56: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	63: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	64: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	65: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	66: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	67: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	68: { lat: 32.78, lng: -96.80, label: 'Dallas, US' },
	69: { lat: 37.39, lng: -122.08, label: 'Mountain View, US' },
	70: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	71: { lat: 43.65, lng: -79.38, label: 'Toronto, CA' },
	72: { lat: 34.05, lng: -118.24, label: 'Los Angeles, US' },
	73: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	74: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	75: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	76: { lat: 45.50, lng: -73.57, label: 'Montreal, CA' },
	96: { lat: 32.78, lng: -96.80, label: 'Dallas, US' },
	97: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	98: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	99: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	100: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	104: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	107: { lat: 32.78, lng: -96.80, label: 'Dallas, US' },
	108: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	128: { lat: 37.39, lng: -122.08, label: 'Mountain View, US' },
	129: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	130: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	131: { lat: 42.36, lng: -71.06, label: 'Boston, US' },
	132: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	134: { lat: 34.05, lng: -118.24, label: 'Los Angeles, US' },
	135: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	136: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	137: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	138: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	139: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	140: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	142: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	143: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	144: { lat: 34.05, lng: -118.24, label: 'Los Angeles, US' },
	147: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	148: { lat: -33.87, lng: 151.21, label: 'Sydney, AU' },
	149: { lat: 51.51, lng: -0.13, label: 'London, UK' },
	150: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	152: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	155: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	156: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	157: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	158: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	159: { lat: 34.05, lng: -118.24, label: 'Los Angeles, US' },
	160: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	161: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	162: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	163: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	164: { lat: 33.75, lng: -84.39, label: 'Atlanta, US' },
	165: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	166: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	167: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	168: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	169: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	170: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	171: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	172: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	173: { lat: 39.05, lng: -77.49, label: 'Ashburn, US' },
	174: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	175: { lat: -36.85, lng: 174.76, label: 'Auckland, NZ' },
	177: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	179: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	180: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	181: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	182: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	183: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	186: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	187: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	189: { lat: 19.43, lng: -99.13, label: 'Mexico City, MX' },
	190: { lat: -34.61, lng: -58.38, label: 'Buenos Aires, AR' },
	191: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	192: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	196: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	197: { lat: 55.75, lng: 37.62, label: 'Moscow, RU' },
	198: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	199: { lat: 43.65, lng: -79.38, label: 'Toronto, CA' },
	200: { lat: -23.55, lng: -46.63, label: 'São Paulo, BR' },
	201: { lat: 19.43, lng: -99.13, label: 'Mexico City, MX' },
	202: { lat: 35.68, lng: 139.69, label: 'Tokyo, JP' },
	203: { lat: 1.35, lng: 103.82, label: 'Singapore' },
	204: { lat: 43.65, lng: -79.38, label: 'Toronto, CA' },
	205: { lat: 40.71, lng: -74.01, label: 'New York, US' },
	206: { lat: 47.61, lng: -122.33, label: 'Seattle, US' },
	207: { lat: 45.50, lng: -73.57, label: 'Montreal, CA' },
	208: { lat: 48.86, lng: 2.35, label: 'Paris, FR' },
	209: { lat: 37.77, lng: -122.42, label: 'San Francisco, US' },
	210: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	211: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	214: { lat: 19.43, lng: -99.13, label: 'Mexico City, MX' },
	216: { lat: 41.88, lng: -87.63, label: 'Chicago, US' },
	218: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	219: { lat: 37.57, lng: 126.98, label: 'Seoul, KR' },
	220: { lat: -33.87, lng: 151.21, label: 'Sydney, AU' },
	221: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	222: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
	223: { lat: 39.9, lng: 116.4, label: 'Beijing, CN' },
};

// Fallback: hash IP to a deterministic location
function hashIpToGeo(ip: string): { lat: number; lng: number; label: string } {
	let hash = 0;
	for (let i = 0; i < ip.length; i++) {
		hash = ((hash << 5) - hash + ip.charCodeAt(i)) | 0;
	}
	const lat = ((hash & 0xffff) / 0xffff) * 140 - 70; // -70 to 70
	const lng = (((hash >> 16) & 0xffff) / 0xffff) * 360 - 180; // -180 to 180
	return { lat, lng, label: ip };
}

export function ipToGeo(ip: string): { lat: number; lng: number; label: string } {
	if (ip === '-' || ip === '127.0.0.1' || ip === '::1') {
		return { lat: -23.55, lng: -46.63, label: 'localhost' };
	}

	const firstOctet = parseInt(ip.split('.')[0], 10);
	if (!isNaN(firstOctet) && REGION_MAP[firstOctet]) {
		return REGION_MAP[firstOctet];
	}

	return hashIpToGeo(ip);
}

export function aggregateGeoPoints(
	events: { client_ip: string }[]
): GeoPoint[] {
	const map = new Map<string, GeoPoint>();

	for (const event of events) {
		const geo = ipToGeo(event.client_ip);
		const key = `${geo.lat.toFixed(1)},${geo.lng.toFixed(1)}`;

		if (map.has(key)) {
			map.get(key)!.count++;
		} else {
			map.set(key, { ...geo, count: 1 });
		}
	}

	return Array.from(map.values()).sort((a, b) => b.count - a.count);
}

import type { GeoPoint } from './types';
