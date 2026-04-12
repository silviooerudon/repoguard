import { signIn } from "@/auth";

export async function GET() {
  await signIn("github", { redirectTo: "/dashboard" });
}