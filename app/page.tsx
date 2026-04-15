import Link from "next/link";
import { auth } from "@/auth";
import { redirect } from "next/navigation";
import PublicScanInput from "./_components/PublicScanInput";

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
            <a href="#faq" className="text-slate-400 hover:text-slate-100 transition">FAQ</a>
            <Link
              href="/signin"
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

        <PublicScanInput />

        <div className="flex items-center justify-center gap-3 text-xs text-slate-500 mb-8">
          <span className="h-px w-12 bg-slate-800" />
          <span>or</span>
          <span className="h-px w-12 bg-slate-800" />
        </div>

        <div className="flex items-center justify-center gap-4">
          <Link
            href="/signin"
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

      {/* HOW IT WORKS */}
      <section className="border-t border-slate-800/60 bg-slate-900/30">
        <div className="max-w-6xl mx-auto px-6 py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
              How it works
            </h2>
            <p className="text-slate-400">
              Three steps. No setup, no CLI, no config files.
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              {
                step: "01",
                title: "Connect GitHub",
                desc: "Sign in with OAuth. Read-only access to the repos you choose.",
              },
              {
                step: "02",
                title: "Run a scan",
                desc: "Pick a repo. We fetch the file tree and match 16 secret patterns in parallel.",
              },
              {
                step: "03",
                title: "Review findings",
                desc: "Results grouped by severity. File path, line number, masked preview.",
              },
            ].map((item) => (
              <div
                key={item.step}
                className="p-6 rounded-xl border border-slate-800 bg-slate-950/50"
              >
                <div className="text-sm font-mono text-slate-500 mb-3">
                  {item.step}
                </div>
                <h3 className="text-lg font-semibold mb-2">{item.title}</h3>
                <p className="text-sm text-slate-400 leading-relaxed">
                  {item.desc}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* FEATURES */}
      <section id="features" className="border-t border-slate-800/60">
        <div className="max-w-6xl mx-auto px-6 py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
              What we detect
            </h2>
            <p className="text-slate-400">
              16 curated patterns across the secrets developers leak most.
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-6">
            {[
              {
                category: "Cloud providers",
                items: ["AWS Access Keys", "AWS Secret Keys", "Google API Keys"],
                severity: "critical",
              },
              {
                category: "Developer tools",
                items: ["GitHub Personal Tokens", "GitHub OAuth Tokens", "NPM Tokens"],
                severity: "critical",
              },
              {
                category: "Payments & APIs",
                items: ["Stripe Live Keys", "OpenAI API Keys", "SendGrid Keys"],
                severity: "high",
              },
              {
                category: "Communications",
                items: ["Slack Tokens", "Twilio Credentials", "JWT Tokens"],
                severity: "high",
              },
              {
                category: "Databases",
                items: ["Connection Strings with Passwords", "MongoDB URIs"],
                severity: "medium",
              },
              {
                category: "Cryptography",
                items: ["RSA Private Keys", "SSH Private Keys"],
                severity: "critical",
              },
            ].map((group) => (
              <div
                key={group.category}
                className="p-6 rounded-xl border border-slate-800 bg-slate-900/40"
              >
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold">{group.category}</h3>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full border font-mono ${
                      group.severity === "critical"
                        ? "border-red-900/60 bg-red-950/40 text-red-300"
                        : group.severity === "high"
                        ? "border-orange-900/60 bg-orange-950/40 text-orange-300"
                        : "border-yellow-900/60 bg-yellow-950/40 text-yellow-300"
                    }`}
                  >
                    {group.severity}
                  </span>
                </div>
                <ul className="space-y-2">
                  {group.items.map((item) => (
                    <li
                      key={item}
                      className="text-sm text-slate-400 flex items-center gap-2"
                    >
                      <span className="w-1 h-1 rounded-full bg-slate-600" />
                      {item}
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </div>

          <p className="text-center text-xs text-slate-500 mt-12">
            More patterns added regularly based on user reports.
          </p>
        </div>
      </section>

      {/* FAQ */}
      <section id="faq" className="border-t border-slate-800/60">
        <div className="max-w-3xl mx-auto px-6 py-24">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
              Frequently asked
            </h2>
          </div>

          <div className="space-y-4">
            {[
              {
                q: "Do you store my source code?",
                a: "No. We fetch files from the GitHub API only during a scan and discard them immediately after. Findings are stored; code is not.",
              },
              {
                q: "What permissions does RepoGuard need?",
                a: "Read-only access to repository contents and metadata. We never request write access, and we can never modify your code.",
              },
              {
                q: "Can I scan private repositories?",
                a: "Yes. GitHub OAuth lets you grant access to private repos on a per-account basis.",
              },
              {
                q: "How is this different from GitHub secret scanning?",
                a: "GitHub's built-in scanning is free but limited to partner patterns. RepoGuard adds curated patterns, severity grouping, and a focused UI for solo devs and small teams.",
              },
              {
                q: "Can I cancel anytime?",
                a: "Yes. Cancel from your account settings in one click. No phone calls, no dark patterns.",
              },
              {
                q: "Is RepoGuard free?",
                a: "Yes, fully free during the current beta. I'm still figuring out what people value enough to pay for — feedback is very welcome.",
              },
            ].map((item) => (
              <details
                key={item.q}
                className="group p-5 rounded-xl border border-slate-800 bg-slate-900/40 hover:bg-slate-900/60 transition"
              >
                <summary className="flex items-center justify-between cursor-pointer font-medium list-none">
                  <span>{item.q}</span>
                  <span className="text-slate-500 group-open:rotate-45 transition-transform text-xl leading-none">
                    +
                  </span>
                </summary>
                <p className="mt-3 text-sm text-slate-400 leading-relaxed">
                  {item.a}
                </p>
              </details>
            ))}
          </div>
        </div>
      </section>

      {/* FOOTER */}
      <footer className="border-t border-slate-800/60 bg-slate-950">
        <div className="max-w-6xl mx-auto px-6 py-12">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded-md bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center font-bold text-xs">
                R
              </div>
              <span className="text-sm text-slate-400">
                RepoGuard © {new Date().getFullYear()}
              </span>
            </div>
            <div className="flex items-center gap-6 text-sm text-slate-500 flex-wrap justify-center">
              <a href="#features" className="hover:text-slate-300 transition">Features</a>
              <a href="#faq" className="hover:text-slate-300 transition">FAQ</a>
              <Link href="/security" className="hover:text-slate-300 transition">Security</Link>
              <a
                href="https://github.com/silviooerudon/repoguard"
                target="_blank"
                rel="noopener noreferrer"
                className="hover:text-slate-300 transition"
              >
                GitHub
              </a>
            </div>
          </div>

          <div className="mt-8 pt-8 border-t border-slate-800/40 flex flex-col md:flex-row items-center justify-between gap-3">
            <p className="text-xs text-slate-600 text-center md:text-left">
              Built in Dublin by{" "}
              <a
                href="https://www.linkedin.com/in/silvio-junior-de-almeida-gazzoli-78453a8a/"
                target="_blank"
                rel="noopener noreferrer"
                className="text-slate-400 hover:text-slate-200 transition underline decoration-slate-700 underline-offset-2"
              >
                Silvio Gazzoli
              </a>
              {" "}— IAM specialist with 10+ years experience. Not affiliated with GitHub.
            </p>
            <span className="text-xs text-slate-600">
              <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5" />
              Open source
            </span>
          </div>
        </div>
      </footer>
    </main>
  );
}