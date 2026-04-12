import Link from "next/link";
import { auth } from "@/auth";
import { redirect } from "next/navigation";

export default async function Home() {
  const session = await auth();
  if (session) redirect("/dashboard");

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      {/* NAV */}
      <nav className="border-b border-slate-800/60 bg-slate-950/80 backdrop-blur sticky top-0 z-50">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center font-bold text-sm">
              R
            </div>
            <span className="font-semibold tracking-tight">RepoGuard</span>
          </div>
          <div className="flex items-center gap-6 text-sm">
            <a href="#features" className="text-slate-400 hover:text-slate-100 transition">Features</a>
            <a href="#pricing" className="text-slate-400 hover:text-slate-100 transition">Pricing</a>
            <a href="#faq" className="text-slate-400 hover:text-slate-100 transition">FAQ</a>
            <Link
              href="/api/auth/signin"
              className="px-4 py-2 rounded-lg bg-slate-100 text-slate-950 font-medium hover:bg-white transition"
            >
              Sign in
            </Link>
          </div>
        </div>
      </nav>

      {/* HERO */}
      <section className="max-w-6xl mx-auto px-6 pt-24 pb-32 text-center">
        <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-slate-800 bg-slate-900/50 text-xs text-slate-400 mb-8">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          Free during beta
        </div>

        <h1 className="text-5xl md:text-6xl font-bold tracking-tight mb-6 leading-[1.1]">
          Scan your GitHub repos
          <br />
          <span className="bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
            for exposed secrets.
          </span>
        </h1>

        <p className="text-lg text-slate-400 max-w-xl mx-auto mb-10">
          16 curated patterns. Zero config. Results in under 60 seconds.
        </p>

        <div className="flex items-center justify-center gap-4">
          <Link
            href="/api/auth/signin"
            className="px-6 py-3 rounded-lg bg-slate-100 text-slate-950 font-medium hover:bg-white transition"
          >
            Sign in with GitHub
          </Link>
          <a
            href="#features"
            className="px-6 py-3 rounded-lg border border-slate-800 text-slate-300 hover:bg-slate-900 transition"
          >
            See what we detect
          </a>
        </div>

        <p className="text-xs text-slate-500 mt-8">
          Read-only access. We never store your code.
        </p>
      </section>
    </main>
  );
}