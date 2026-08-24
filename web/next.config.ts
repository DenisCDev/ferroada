const nextConfig = {
  async rewrites() {
    const upstream = process.env.FERROADA_URL ?? "http://127.0.0.1:9000";
    return [{ source: "/proxy-metrics", destination: `${upstream}/api/metrics` }];
  },
};

export default nextConfig;
