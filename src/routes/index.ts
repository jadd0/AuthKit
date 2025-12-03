import { NextResponse } from "next/server";
import { routeProviderRequest } from "./providers";
import { routeSessionRequest } from "./session";
import { auth } from "../client";

/** Used to handle the first segment route */
export async function routeMainAuthRequest(
  segments: string[],
  method: string,
  body: any,
  parsedCookies: Record<string, string>
): Promise<Response> {
  // Provider handler
  switch (segments[0]) {
    case "provider":
      return await routeProviderRequest(segments, method, body);

    case "session":
      return await routeSessionRequest(segments, method, body, parsedCookies);

    case "health":
      const authInit = auth ? true : false
      ;
      return NextResponse.json(
        { status: "ok", authInitialized: authInit },
        { status: 200 }
      );

    case "option":
      

    default:
      return NextResponse.json({ message: "Route not found" }, { status: 404 });
  }
}
