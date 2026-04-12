import { auth, signOut } from "@/auth"
import { redirect } from "next/navigation"

export default async function Dashboard() {
  const session = await auth()

  // Guard: se não tem sessão, volta pra landing
  if (!session) {
    redirect("/")
  }

  return (
    <main className="min-h-screen bg-gradient-to-b from-gray-950 to-gray-900 text-white px-6 py-12">
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center justify-between mb-12">
          <h1 className="text-3xl font-bold">
            Repo<span className="text-blue-500">Guard</span>
          </h1>

          <form
            action={async () => {
              "use server"
              await signOut({ redirectTo: "/" })
            }}
          >
            <button
              type="submit"
              className="px-4 py-2 rounded-lg border border-gray-700 hover:border-gray-500 transition text-sm font-medium"
            >
              Sign out
            </button>
          </form>
        </div>

        <div className="bg-gray-900 border border-gray-800 rounded-xl p-8">
          <div className="flex items-center gap-4 mb-6">
            {session?.user?.image && (
              <img
                src={session.user.image}
                alt={session.user.name ?? "User"}
                className="w-16 h-16 rounded-full border-2 border-gray-700"
              />
            )}
            <div>
              <h2 className="text-2xl font-semibold">
                Welcome, {session?.user?.name ?? "there"}!
              </h2>
              <p className="text-gray-400 text-sm">
                {session?.user?.email}
              </p>
            </div>
          </div>

          <div className="mt-8 p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
            <p className="text-green-400 text-sm">
              ✅ You are successfully authenticated with GitHub. Next up: repository scanning.
            </p>
          </div>
        </div>

        <p className="text-center text-gray-600 text-sm mt-8">
          🚧 This dashboard is a work in progress. Scanning features coming soon.
        </p>
      </div>
    </main>
  )
}