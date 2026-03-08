import { motion } from "framer-motion";
import type { AnalysisSignals } from "@/lib/analyzer";

interface SignalBarsProps {
  signals: AnalysisSignals;
}

const SignalBars = ({ signals }: SignalBarsProps) => {
  const bars = [
    { label: "AI Generated", value: signals.ai_generated, icon: "🤖" },
    { label: "Scam Keywords", value: signals.scam_keywords, icon: "🎣" },
    { label: "Emotional Manipulation", value: signals.emotional_manipulation, icon: "😰" },
  ];

  const getColor = (value: number) =>
    value < 30 ? "bg-success" : value < 65 ? "bg-warning" : "bg-destructive";

  return (
    <div className="space-y-4">
      {bars.map((bar, i) => (
        <div key={bar.label} className="space-y-1.5">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 font-medium">
              <span>{bar.icon}</span>
              {bar.label}
            </span>
            <span className="font-mono text-muted-foreground">{bar.value}%</span>
          </div>
          <div className="h-2.5 rounded-full bg-secondary overflow-hidden">
            <motion.div
              className={`h-full rounded-full ${getColor(bar.value)}`}
              initial={{ width: 0 }}
              animate={{ width: `${bar.value}%` }}
              transition={{ duration: 0.8, delay: i * 0.15, ease: "easeOut" }}
            />
          </div>
        </div>
      ))}
    </div>
  );
};

export default SignalBars;
