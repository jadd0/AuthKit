import type { Config } from "drizzle-kit";

export default {
  schema: "./src/shared/schemas/",   
  out: "./drizzle",             
  dialect: "postgresql",
} satisfies Config;