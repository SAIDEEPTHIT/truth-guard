import { motion } from "framer-motion";

interface RiskGaugeProps {
  score: number;
  classification: string;
  size?: "sm" | "lg";
}

const RiskGauge = ({ score, classification, size = "lg" }: RiskGaugeProps) => {
  const dims = size === "lg" ? { w: 180, h: 180, stroke: 12 } : { w: 100, h: 100, stroke: 8 };
  const radius = (dims.w - dims.stroke * 2) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = (score / 100) * circumference;

  const color =
    classification === "Safe" || classification === "Likely Authentic"
      ? "hsl(142, 71%, 45%)"
      : classification === "Suspicious" || classification === "Possibly AI-Generated"
      ? "hsl(45, 93%, 47%)"
      : "hsl(0, 72%, 51%)";

  const bgClass =
    classification === "Safe" || classification === "Likely Authentic"
      ? "shadow-glow-safe"
      : classification === "Suspicious" || classification === "Possibly AI-Generated"
      ? ""
      : "shadow-glow-danger";

  return (
    <div className={`relative inline-flex flex-col items-center ${bgClass} rounded-full`}>
      <svg width={dims.w} height={dims.w} className="-rotate-90">
        <circle
          cx={dims.w / 2}
          cy={dims.w / 2}
          r={radius}
          fill="transparent"
          stroke="hsl(var(--border))"
          strokeWidth={dims.stroke}
        />
        <motion.circle
          cx={dims.w / 2}
          cy={dims.w / 2}
          r={radius}
          fill="transparent"
          stroke={color}
          strokeWidth={dims.stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: circumference - progress }}
          transition={{ duration: 1.2, ease: "easeOut" }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <motion.span
          className="font-mono font-bold"
          style={{ fontSize: size === "lg" ? 40 : 22, color }}
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
        >
          {score}
        </motion.span>
        <span className="text-xs text-muted-foreground font-medium uppercase tracking-wider">
          /100
        </span>
      </div>
    </div>
  );
};

export default RiskGauge;
