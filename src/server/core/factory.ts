import type { AuthConfig } from "@/server/index";
import { getAuthInstance } from "./singleton";
import { routeAuthRequest } from "./router";

// Web API Request/Response are standard in Next route handlers
type WebHandler = (req: Request) => Promise<Response> | Response;

// The public factory that developers call in src/auth.ts
export default function AuthKit(config: AuthConfig) {
  // Ensure the instance is created lazily and reused
  let ready: ReturnType<typeof getAuthInstance> | null = null;
  const ensure = () => (ready ??= getAuthInstance(config));

  // Shared router for GET/POST
  const route: WebHandler = async (req) => {
    await ensure();
    return routeAuthRequest(req);
  };

  const GET: WebHandler = (req) => route(req);
  const POST: WebHandler = (req) => route(req);

  // Usable in middleware (Edge/Node) and in server components/actions
  const auth = async (req?: Request) => {
    const auth = await ensure();
    return auth.hello();
  };

  return {
    handlers: { GET, POST }, // For app/api/auth/[...authkit]/route.ts
    auth, // For server components/actions/middleware
  };
}
