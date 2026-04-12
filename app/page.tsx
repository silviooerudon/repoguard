import { auth, signIn, signOut } from "@/auth"
import { redirect } from "next/navigation"

export default async function Home() {
  const session = await auth()

  // Se já logado, manda direto pro dashboard
  if (session) {
    redirect("/dashboard")
  }

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-950 to-gray-900 text-white flex items-center justify-center px-6">
      <div className="max-w-2xl text-center">
        <div className="inline-block mb-6 px-4 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-sm font-medium">
          🛡️ Security for your GitHub repos
        </div>

        <h1 className="text-5xl sm:text-6xl font-bold tracking-tight mb-6">
          Repo<span className="text-blue-500">Guard</span>
        </h1>

        <p className="text-lg sm:text-xl text-gray-400 mb-10 leading-relaxed">
          Find exposed secrets, vulnerable dependencies, and misconfigurations
          in your GitHub repositories — before someone else does.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <form
            action={async () => {
              "use server"
              await signIn("github", { redirectTo: "/dashboard" })
            }}
          >
            <button
              type="submit"
              className="w-full sm:w-auto px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 transition font-semibold flex items-center gap-2 justify-center"
            >
              <svg
                className="w-5 h-5"
                viewBox="0 0 24 24"
                fill="currentColor"
              >
                <path d="M12 .297c-6.63 0-12 5.373-12 12 0 5.303 3.438 9.8 8.205 11.385.6.113.82-.258.82-.577 0-.285-.01-1.04-.015-2.04-3.338.724-4.042-1.61-4.042-1.61C4.422 18.07 3.633 17.7 3.633 17.7c-1.087-.744.084-.729.084-.729 1.205.084 1.838 1.236 1.838 1.236 1.07 1.835 2.809 1.305 3.495.998.108-.776.417-1.305.76-1.605-2.665-.3-5.466-1.332-5.466-5.93 0-1.31.465-2.38 1.235-3.22-.135-.303-.54-1.523.105-3.176 0 0 1.005-.322 3.3 1.23.96-.267 1.98-.399 3-.405 1.02.006 2.04.138 3 .405 2.28-1.552 3.285-1.23 3.285-1.23.645 1.653.24 2.873.12 3.176.765.84 1.23 1.91 1.23 3.22 0 4.61-2.805 5.625-5.475 5.92.42.36.81 1.096.81 2.22 0 1.606-.015 2.896-.015 3.286 0 .315.21.69.825.57C20.565 22.092 24 17.592 24 12.297c0-6.627-5.373-12-12-12" />
              </svg>
              Sign in with GitHub
            </button>
          </form>

          <button
            type="button"
            className="px-6 py-3 rounded-lg border border-gray-700 hover:border-gray-500 transition font-semibold"
          >
            See how it works
          </button>
        </div>

        <p className="text-sm text-gray-600 mt-8">
          Free for 1 repository. No credit card required.
        </p>
      </div>
    </main>
  )
}