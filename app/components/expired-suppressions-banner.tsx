type Props = { count: number }

export function ExpiredSuppressionsBanner({ count }: Props) {
  if (count === 0) return null
  const word = count === 1 ? "suppression" : "suppressions"
  return (
    <div
      role="alert"
      className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-4 text-yellow-200"
    >
      <p className="text-sm">
        <strong className="font-semibold">
          {count} expired {word}
        </strong>{" "}
        in your <code className="font-mono text-xs">.repoguardignore</code>.
        Review and update or remove them - expired rules still suppress
        findings until you act.
      </p>
    </div>
  )
}