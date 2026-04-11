export default function Home() {
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
          <button className="px-6 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 transition font-semibold">
            Scan my repos
          </button>
          <button className="px-6 py-3 rounded-lg border border-gray-700 hover:border-gray-500 transition font-semibold">
            See how it works
          </button>
        </div>

        <p className="text-sm text-gray-600 mt-8">
          Free for 1 repository. No credit card required.
        </p>
      </div>
    </main>
  );
}