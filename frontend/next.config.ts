import type { NextConfig } from "next";

/** A publishable key is pk_<env>_<base64 of the Clerk Frontend API host + "$">. */
function clerkHost(): string | null {
  const encoded = process.env.NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY?.split("_")[2];
  if (!encoded) return null;
  const host = Buffer.from(encoded, "base64").toString().replace(/\$$/, "");
  return /^[a-z0-9.-]+$/i.test(host) ? `https://${host}` : null;
}

function originOf(url: string | undefined): string | null {
  try {
    return url ? new URL(url).origin : null;
  } catch {
    return null;
  }
}

function contentSecurityPolicy(): string {
  const dev = process.env.NODE_ENV !== "production";
  const clerk = clerkHost();
  const turnstile = "https://challenges.cloudflare.com";
  const source = (...values: (string | null | false)[]) => values.filter(Boolean).join(" ");
  return [
    "default-src 'self'",
    `script-src ${source("'self'", "'unsafe-inline'", dev && "'unsafe-eval'", clerk, "https://cdn.protect.clerk.com", turnstile)}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https://img.clerk.com",
    "font-src 'self'",
    `connect-src ${source("'self'", originOf(process.env.NEXT_PUBLIC_API_URL), originOf(process.env.NEXT_PUBLIC_RPC_URL), clerk, "https://*.protect.clerk.com", "https://clerk-telemetry.com", dev && "ws:")}`,
    "worker-src 'self' blob:",
    `frame-src ${turnstile}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}

const nextConfig: NextConfig = {
  poweredByHeader: false,
  cacheComponents: true,
  partialPrefetching: true,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async headers() {
    return [
      {
        source: "/:path*",
        headers: [
          { key: "Content-Security-Policy", value: contentSecurityPolicy() },
          { key: "X-Content-Type-Options", value: "nosniff" },
          { key: "X-Frame-Options", value: "DENY" },
          { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
          { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
        ],
      },
    ];
  },
};

export default nextConfig;
