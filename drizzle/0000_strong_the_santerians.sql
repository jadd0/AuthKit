CREATE TABLE "accounts" (
	"userId" varchar NOT NULL,
	"type" varchar,
	"provider" varchar NOT NULL,
	"providerAccountId" varchar,
	"refreshToken" varchar,
	"accessToken" varchar,
	"expiresAt" integer,
	"idToken" text,
	"scope" varchar,
	"tokenType" varchar,
	"password" varchar,
	"passwordHash" varchar,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "accounts_userId_provider_pk" PRIMARY KEY("userId","provider")
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" varchar PRIMARY KEY NOT NULL,
	"sessionToken" varchar NOT NULL,
	"userId" varchar NOT NULL,
	"lastActivityAt" timestamp DEFAULT now(),
	"createdAt" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "sessions_sessionToken_unique" UNIQUE("sessionToken")
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" varchar PRIMARY KEY NOT NULL,
	"username" varchar,
	"name" varchar NOT NULL,
	"email" varchar NOT NULL,
	"emailVerified" timestamp,
	"image" varchar,
	"createdAt" timestamp DEFAULT now() NOT NULL,
	"updatedAt" timestamp DEFAULT now() NOT NULL,
	CONSTRAINT "users_username_unique" UNIQUE("username"),
	CONSTRAINT "users_email_unique" UNIQUE("email")
);
--> statement-breakpoint
ALTER TABLE "accounts" ADD CONSTRAINT "accounts_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_userId_users_id_fk" FOREIGN KEY ("userId") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;