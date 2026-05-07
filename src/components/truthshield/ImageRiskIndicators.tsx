import { motion } from "framer-motion";
import { Shield, Download, Flag, Lightbulb, BarChart3 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useSeniorMode } from "@/contexts/SeniorModeContext";

interface ScoreBreakdown {
  metadata: number;
  pixelAnalysis: number;
  aiModel: number | null;
  weights: { metadata: number; pixelAnalysis: number; aiModel: number };
}

interface FlagItem {
  flag: string;
  label: string;
  severity: string;
  detail: string;
}

interface Recommendation {
  level: string;
  title: string;
  message: string;
  icon: string;
  color: string;
}

interface Props {
  riskScore: number;
  classification: string;
  confidence: number;
  flags: FlagItem[];
  recommendation: Recommendation;
  scoreBreakdown: ScoreBreakdown;
  tips: string[];
  fullResult: Record<string, unknown>;
}

const ImageRiskIndicators = ({ riskScore, classification, confidence, flags, recommendation, scoreBreakdown, tips, fullResult }: Props) => {
  const { seniorMode } = useSeniorMode();

  const getScoreColor = () => {
    if (riskScore <= 30) return "border-emerald-500 text-emerald-400";
    if (riskScore <= 60) return "border-yellow-500 text-yellow-400";
    return "border-red-500 text-red-400";
  };

  const getScoreBgGlow = () => {
    if (riskScore <= 30) return "shadow-[0_0_40px_rgba(16,185,129,0.15)]";
    if (riskScore <= 60) return "shadow-[0_0_40px_rgba(234,179,8,0.15)]";
    return "shadow-[0_0_40px_rgba(239,68,68,0.2)]";
  };

  const getRecommendationBg = () => {
    switch (recommendation.color) {
      case "green": return "bg-emerald-500/10 border-emerald-500/30";
      case "yellow": return "bg-yellow-500/10 border-yellow-500/30";
      case "red": return "bg-red-500/10 border-red-500/30";
      default: return "bg-muted/50 border-border";
    }
  };

  const handleExportReport = () => {
    const report = JSON.stringify(fullResult, null, 2);
    const blob = new Blob([report], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `truthshield-image-report-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-4">
      {/* Overall Risk Score */}
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className={`rounded-xl border border-border bg-card p-6 text-center ${getScoreBgGlow()}`}
      >
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: "spring", stiffness: 200, delay: 0.2 }}
          className={`inline-flex items-center justify-center w-28 h-28 rounded-full border-[6px] ${getScoreColor()}`}
        >
          <span className="text-4xl font-black">{riskScore}</span>
        </motion.div>

        <motion.p
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className={`mt-3 font-black uppercase tracking-widest ${
            riskScore <= 30 ? "text-emerald-400" : riskScore <= 60 ? "text-yellow-400" : "text-red-400"
          } ${seniorMode ? "text-xl" : "text-lg"}`}
        >
          {seniorMode
            ? riskScore <= 30 ? "✅ This photo looks real!" : riskScore <= 60 ? "⚠️ Not sure — be careful" : "🚨 Probably fake!"
            : classification
          }
        </motion.p>

        <p className="text-xs text-muted-foreground mt-1">
          Confidence: <span className="font-bold text-foreground">{confidence}%</span>
        </p>
      </motion.div>

      {/* Score Breakdown */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <BarChart3 className="w-4 h-4" /> Score Breakdown
        </h3>
        <div className="space-y-3">
          <BreakdownBar
            label="Metadata Analysis"
            score={scoreBreakdown.metadata}
            weight={scoreBreakdown.weights.metadata}
          />
          <BreakdownBar
            label="Pixel Analysis"
            score={scoreBreakdown.pixelAnalysis}
            weight={scoreBreakdown.weights.pixelAnalysis}
          />
          {scoreBreakdown.aiModel != null && (
            <BreakdownBar
              label="AI Model Detection"
              score={scoreBreakdown.aiModel}
              weight={scoreBreakdown.weights.aiModel}
            />
          )}
        </div>
      </motion.div>

      {/* Flags */}
      {flags.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl border border-border bg-card p-4"
        >
          <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
            <Flag className="w-4 h-4" /> Red Flags Found ({flags.length})
          </h3>
          <div className="space-y-2">
            {flags.map((f, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + i * 0.05 }}
                className={`flex items-start gap-2.5 p-2.5 rounded-lg border ${
                  f.severity === "high"
                    ? "bg-red-500/10 border-red-500/20"
                    : "bg-yellow-500/10 border-yellow-500/20"
                }`}
              >
                <span className="text-sm mt-0.5">{f.severity === "high" ? "🔴" : "⚠️"}</span>
                <div>
                  <p className={`font-medium ${seniorMode ? "text-sm" : "text-xs"}`}>{f.label}</p>
                  <p className="text-xs text-muted-foreground">{f.detail}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}

      {/* Recommendation */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className={`rounded-xl border p-4 ${getRecommendationBg()}`}
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
          <Shield className="w-4 h-4" /> Recommendation
        </h3>
        <div className="flex items-start gap-3">
          <span className="text-2xl">{recommendation.icon}</span>
          <div>
            <p className={`font-bold ${seniorMode ? "text-base" : "text-sm"}`}>
              {recommendation.title}
            </p>
            <p className={`text-muted-foreground mt-1 ${seniorMode ? "text-sm" : "text-xs"}`}>
              {recommendation.message}
            </p>
          </div>
        </div>
      </motion.div>

      {/* Tips */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.5 }}
        className="rounded-xl border border-primary/20 bg-primary/5 p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-2">
          <Lightbulb className="w-4 h-4" /> Tips
        </h3>
        <ul className="space-y-1.5">
          {tips.map((tip, i) => (
            <li key={i} className={`flex items-start gap-2 ${seniorMode ? "text-sm" : "text-xs"} text-muted-foreground`}>
              <span className="text-primary mt-0.5">💡</span>
              {tip}
            </li>
          ))}
        </ul>
      </motion.div>

      {/* Export */}
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.6 }}
        className="flex gap-2"
      >
        <Button onClick={handleExportReport} variant="outline" className="flex-1 gap-2">
          <Download className="w-4 h-4" /> Download Report (JSON)
        </Button>
      </motion.div>
    </div>
  );
};

const BreakdownBar = ({ label, score, weight }: { label: string; score: number; weight: number }) => (
  <div>
    <div className="flex justify-between text-xs mb-1">
      <span className="text-muted-foreground">{label} ({Math.round(weight * 100)}%)</span>
      <span className={`font-bold ${score <= 30 ? "text-emerald-400" : score <= 60 ? "text-yellow-400" : "text-red-400"}`}>
        {score}
      </span>
    </div>
    <div className="h-2.5 rounded-full bg-muted/50 overflow-hidden">
      <motion.div
        initial={{ width: 0 }}
        animate={{ width: `${score}%` }}
        transition={{ duration: 0.8, ease: "easeOut" }}
        className={`h-full rounded-full ${
          score <= 30 ? "bg-emerald-500" : score <= 60 ? "bg-yellow-500" : "bg-red-500"
        }`}
      />
    </div>
  </div>
);

export default ImageRiskIndicators;
