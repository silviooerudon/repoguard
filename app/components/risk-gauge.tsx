type RiskGaugeProps = {
  score: number
  size?: number
}

function colorForScore(score: number): string {
  if (score <= 20) return "#22c55e"
  if (score <= 50) return "#eab308"
  if (score <= 80) return "#f97316"
  return "#ef4444"
}

function labelForScore(score: number): string {
  if (score <= 20) return "Clean"
  if (score <= 50) return "Attention"
  if (score <= 80) return "High risk"
  return "Critical"
}

export function RiskGauge({ score, size = 160 }: RiskGaugeProps) {
  const clamped = Math.max(0, Math.min(100, Math.round(score)))
  const stroke = Math.max(8, Math.round(size * 0.08))
  const radius = (size - stroke) / 2
  const cx = size / 2
  const cy = size / 2

  const sweepDeg = 270
  const circumference = 2 * Math.PI * radius
  const arcLength = circumference * (sweepDeg / 360)
  const progress = arcLength * (clamped / 100)
  const gap = circumference - arcLength

  const rotation = 135

  const color = colorForScore(clamped)
  const label = labelForScore(clamped)

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative" style={{ width: size, height: size }}>
        <svg
          width={size}
          height={size}
          viewBox={`0 0 ${size} ${size}`}
          style={{ transform: `rotate(${rotation}deg)` }}
        >
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke="#1f2937"
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${arcLength} ${gap}`}
          />
          <circle
            cx={cx}
            cy={cy}
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth={stroke}
            strokeLinecap="round"
            strokeDasharray={`${progress} ${circumference - progress}`}
            style={{ transition: "stroke-dasharray 300ms ease, stroke 300ms ease" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span
            className="font-bold text-white leading-none"
            style={{ fontSize: Math.round(size * 0.32) }}
          >
            {clamped}
          </span>
          <span
            className="text-gray-500 mt-1"
            style={{ fontSize: Math.round(size * 0.1) }}
          >
            / 100
          </span>
        </div>
      </div>
      <div
        className="mt-2 text-xs uppercase tracking-wider font-semibold"
        style={{ color }}
      >
        {label}
      </div>
    </div>
  )
}

export default RiskGauge
