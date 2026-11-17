const securityHeaders = [
  { key: 'Content-Security-Policy', value: "default-src 'self'; frame-ancestors 'none'" },
  { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
  { key: 'X-Frame-Options', value: 'DENY' },
  { key: 'X-Content-Type-Options', value: 'nosniff' },
];
module.exports = { async headers() { return [{ source: '/(.*)', headers: securityHeaders }]; } };
