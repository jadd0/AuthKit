import { NextResponse } from "next/server";
import { routeEmailPasswordProviderRequest } from "./emailPasssword";

/** Used to handle the provider request route */
export async function routeProviderRequest(
  segments: string[],
  method: string,
  body: any
): Promise<Response> {
  switch (segments[1]) {
    case "emailPassword":
      return await routeEmailPasswordProviderRequest(segments, method, body);

    default:
      return NextResponse.json(
        { message: "Provider not found" },
        { status: 404 }
      );
  }
}
