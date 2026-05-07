import { motion } from "framer-motion";
import { Cpu, Scan, Zap, AlertTriangle, CheckCircle2, Info } from "lucide-react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";

interface PixelAnalysis {
  noiseDistribution: string;
  noiseScore: number;
  colorGradients: string;
  gradientScore: number;
  compressionArtifacts: boolean;
  compressionScore: number;
  patternConsistency: string;
  patternScore: number;
  overallScore: number;
  indicators: Array<{ signal: string; detail: string; severity: string; type: string }>;
}

interface AIDetection {
  score: number;
  model: string;
  available: boolean;
}

interface Props {
  pixelAnalysis: PixelAnalysis;
  aiDetection: AIDetection;
}

const AIDetectionPanel = ({ pixelAnalysis, aiDetection }: Props) => {
  const { seniorMode } = useSeniorMode();

  const getStatusBadge = (status: string) => {
    const isNormal = status === "normal" || status === "consistent";
    return (
      <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold uppercase ${
        isNormal
          ? "bg-emerald-500/20 text-emerald-400"
          : "bg-red-500/20 text-red-400"
      }`}>
        {isNormal ? "✅ Normal" : "⚠️ Suspicious"}
      </span>
    );
  };

  const getScoreBar = (score: number, label: string) => (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className={`font-bold ${score <= 30 ? "text-emerald-400" : score <= 60 ? "text-yellow-400" : "text-red-400"}`}>
          {score}%
        </span>
      </div>
      <div className="h-2 rounded-full bg-background/50 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className={`h-full rounded-full ${
            score <= 30 ? "bg-emerald-500" : score <= 60 ? "bg-yellow-500" : "bg-red-500"
          }`}
        />
      </div>
    </div>
  );

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case "green": return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />;
      case "red": return <AlertTriangle className="w-3.5 h-3.5 text-red-400 shrink-0" />;
      default: return <Info className="w-3.5 h-3.5 text-yellow-400 shrink-0" />;
    }
  };

  return (
    <div className="space-y-4">
      {/* Pixel Analysis */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-4">
          <Scan className="w-4 h-4" /> Pixel Pattern Analysis
        </h3>

        <div className="space-y-3">
          <div className="flex items-center justify-between p-2.5 rounded-lg bg-muted/30">
            <span className={`${seniorMode ? "text-sm" : "text-xs"}`}>Noise Distribution</span>
            {getStatusBadge(pixelAnalysis.noiseDistribution)}
          </div>
          <div className="flex items-center justify-between p-2.5 rounded-lg bg-muted/30">
            <span className={`${seniorMode ? "text-sm" : "text-xs"}`}>Color Gradients</span>
            {getStatusBadge(pixelAnalysis.colorGradients)}
          </div>
          <div className="flex items-center justify-between p-2.5 rounded-lg bg-muted/30">
            <span className={`${seniorMode ? "text-sm" : "text-xs"}`}>Compression Artifacts</span>
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-bold uppercase ${
              !pixelAnalysis.compressionArtifacts
                ? "bg-emerald-500/20 text-emerald-400"
                : "bg-yellow-500/20 text-yellow-400"
            }`}>
              {pixelAnalysis.compressionArtifacts ? "⚠️ Found" : "✅ Clean"}
            </span>
          </div>
          <div className="flex items-center justify-between p-2.5 rounded-lg bg-muted/30">
            <span className={`${seniorMode ? "text-sm" : "text-xs"}`}>Pattern Consistency</span>
            {getStatusBadge(pixelAnalysis.patternConsistency)}
          </div>
        </div>

        <div className="mt-4 space-y-2.5">
          {getScoreBar(pixelAnalysis.noiseScore, "Noise Score")}
          {getScoreBar(pixelAnalysis.gradientScore, "Gradient Score")}
          {getScoreBar(pixelAnalysis.compressionScore, "Compression Score")}
          {getScoreBar(pixelAnalysis.patternScore, "Pattern Score")}
        </div>
      </motion.div>

      {/* HuggingFace AI Detection */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.15 }}
        className={`rounded-xl border p-4 ${
          aiDetection.available
            ? aiDetection.score > 60
              ? "border-red-500/40 bg-red-500/5"
              : aiDetection.score > 30
              ? "border-yellow-500/40 bg-yellow-500/5"
              : "border-emerald-500/40 bg-emerald-500/5"
            : "border-border bg-card"
        }`}
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <Cpu className="w-4 h-4" /> AI Model Detection
        </h3>

        {aiDetection.available ? (
          <div className="space-y-3">
            <div className="text-center">
              <motion.div
                initial={{ scale: 0 }}
                animate={{ scale: 1 }}
                transition={{ type: "spring", stiffness: 200 }}
                className={`inline-flex items-center justify-center w-20 h-20 rounded-full border-4 ${
                  aiDetection.score > 60
                    ? "border-red-500 text-red-400"
                    : aiDetection.score > 30
                    ? "border-yellow-500 text-yellow-400"
                    : "border-emerald-500 text-emerald-400"
                }`}
              >
                <span className="text-2xl font-black">{aiDetection.score}%</span>
              </motion.div>
              <p className={`mt-2 font-bold uppercase tracking-wider ${
                aiDetection.score > 60 ? "text-red-400" : aiDetection.score > 30 ? "text-yellow-400" : "text-emerald-400"
              } ${seniorMode ? "text-base" : "text-sm"}`}>
                {aiDetection.score > 60
                  ? seniorMode ? "🚨 Probably Computer-Made" : "AI-Generated"
                  : aiDetection.score > 30
                  ? seniorMode ? "⚠️ Not Sure" : "Uncertain"
                  : seniorMode ? "✅ Looks Real" : "Likely Authentic"
                }
              </p>
            </div>
            <div className="text-xs text-muted-foreground text-center space-y-1">
              <p>Model: <span className="font-mono text-foreground">{aiDetection.model}</span></p>
              <p>Confidence: <span className="font-bold text-foreground">
                {aiDetection.score > 80 ? "High" : aiDetection.score > 50 ? "Medium" : "Low"}
              </span></p>
            </div>
          </div>
        ) : (
          <div className="text-center py-4">
            <Zap className="w-8 h-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-xs text-muted-foreground">
              HuggingFace API unavailable — using local analysis only
            </p>
            <p className="text-xs text-muted-foreground/60 mt-1">
              Results based on metadata + pixel analysis
            </p>
          </div>
        )}
      </motion.div>

      {/* Detection Indicators */}
      {pixelAnalysis.indicators.length > 0 && (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="rounded-xl border border-border bg-card p-4"
        >
          <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
            AI Generation Indicators
          </h3>
          <div className="space-y-2">
            {pixelAnalysis.indicators.map((ind, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.3 + i * 0.05 }}
                className="flex items-start gap-2 text-sm"
              >
                {getIndicatorIcon(ind.type)}
                <div>
                  <p className={`font-medium ${seniorMode ? "text-sm" : "text-xs"}`}>{ind.signal}</p>
                  <p className="text-xs text-muted-foreground">{ind.detail}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>
      )}
    </div>
  );
};

export default AIDetectionPanel;
