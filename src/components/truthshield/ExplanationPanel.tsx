import { motion } from "framer-motion";
import type { Explanation } from "@/lib/analyzer";
import { AlertTriangle, Bot, Flame, MapPin } from "lucide-react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";

interface ExplanationPanelProps {
  explanations: Explanation[];
  summary: string;
  tips: string[];
}

const categoryConfig = {
  scam: { icon: AlertTriangle, label: "Scam Indicator", color: "text-destructive", bg: "bg-destructive/10" },
  urgency: { icon: Flame, label: "Emotional Manipulation", color: "text-warning", bg: "bg-warning/10" },
  ai: { icon: Bot, label: "AI Pattern", color: "text-accent", bg: "bg-accent/10" },
  india_scam: { icon: MapPin, label: "India-Specific Scam", color: "text-destructive", bg: "bg-destructive/10" },
};

const severityBadge = {
  low: "bg-success/20 text-success",
  medium: "bg-warning/20 text-warning",
  high: "bg-destructive/20 text-destructive",
};

const ExplanationPanel = ({ explanations, summary, tips }: ExplanationPanelProps) => {
  const { seniorMode } = useSeniorMode();

  return (
    <div className="space-y-6">
      {/* Summary */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="p-4 rounded-lg border border-border bg-card"
      >
        <h3 className={`font-semibold mb-2 ${seniorMode ? "text-xl" : "text-base"}`}>
          📋 Analysis Summary
        </h3>
        <p className={`text-muted-foreground leading-relaxed ${seniorMode ? "text-lg" : "text-sm"}`}>
          {summary}
        </p>
      </motion.div>

      {/* Explanations */}
      {explanations.length > 0 && (
        <div>
          <h3 className={`font-semibold mb-3 ${seniorMode ? "text-xl" : "text-base"}`}>
            🔍 Why This Was Flagged
          </h3>
          <div className="space-y-2">
            {explanations.map((exp, i) => {
              const config = categoryConfig[exp.category];
              const Icon = config.icon;
              return (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.05 }}
                  className={`p-3 rounded-lg border border-border ${config.bg}`}
                >
                  <div className="flex items-start gap-3">
                    <Icon className={`w-4 h-4 mt-0.5 ${config.color} shrink-0`} />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap mb-1">
                        <span className={`text-xs font-medium ${config.color}`}>{config.label}</span>
                        <span className={`text-xs px-1.5 py-0.5 rounded ${severityBadge[exp.severity]}`}>
                          {exp.severity}
                        </span>
                        {exp.phrase !== "(stylometric pattern)" && (
                          <code className="text-xs bg-secondary px-1.5 py-0.5 rounded font-mono">
                            "{exp.phrase}"
                          </code>
                        )}
                      </div>
                      <p className={`text-muted-foreground ${seniorMode ? "text-base" : "text-xs"}`}>
                        {exp.reason}
                      </p>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tips */}
      {tips.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="p-4 rounded-lg border border-primary/20 bg-primary/5"
        >
          <h3 className={`font-semibold mb-2 ${seniorMode ? "text-xl" : "text-base"}`}>
            💡 Safety Tips
          </h3>
          <ul className="space-y-1.5">
            {tips.map((tip, i) => (
              <li key={i} className={`flex items-start gap-2 ${seniorMode ? "text-base" : "text-sm"} text-muted-foreground`}>
                <span className="text-primary mt-0.5">•</span>
                {tip}
              </li>
            ))}
          </ul>
        </motion.div>
      )}
    </div>
  );
};

export default ExplanationPanel;
