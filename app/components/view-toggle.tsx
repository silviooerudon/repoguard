type ViewToggleButtonProps = {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}

export function ViewToggleButton({
  active,
  onClick,
  children,
}: ViewToggleButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-xs px-3 py-1.5 rounded-full border transition ${
        active
          ? "bg-blue-500/15 border-blue-500/30 text-blue-300"
          : "bg-gray-900 border-gray-800 text-gray-400 hover:text-gray-200"
      }`}
    >
      {children}
    </button>
  )
}
