import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ImageIcon, Upload, Loader2, RotateCcw, ExternalLink } from "lucide-react";
import { analyzeImage, type ImageAnalysisResult } from "@/lib/analyzer";
import { addToHistory } from "./AnalysisHistory";
import { recordAnalysis } from "@/lib/analysisStore";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import RiskGauge from "./RiskGauge";
import { Button } from "@/components/ui/button";

const ImageAnalyzer = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [result, setResult] = useState<ImageAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const { seniorMode } = useSeniorMode();

  const handleFile = useCallback(async (f: File) => {
    if (!f.type.startsWith("image/")) return;
    setFile(f);
    setPreview(URL.createObjectURL(f));
    setResult(null);
    setLoading(true);
    await new Promise(r => setTimeout(r, 1000));
    const analysis = await analyzeImage(f);
    setResult(analysis);
    addToHistory("image", f.name, analysis.risk_score, analysis.classification);
    recordAnalysis({
      type: "image",
      input_preview: f.name,
      risk_score: analysis.risk_score,
      classification: analysis.classification,
      signals: { ai_generated: analysis.risk_score, scam_keywords: 0, emotional_manipulation: 0 },
    });
    setLoading(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(false);
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  }, [handleFile]);

  const handleReset = () => {
    setFile(null);
    setPreview(null);
    setResult(null);
  };

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className={`font-bold mb-2 ${seniorMode ? "text-3xl" : "text-2xl"}`}>
            <ImageIcon className="w-6 h-6 inline-block mr-2 text-primary" />
            Image Analysis
          </h1>
          <p className={`text-muted-foreground ${seniorMode ? "text-lg" : "text-sm"}`}>
            Upload an image to check if it may be AI-generated or manipulated.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Upload area */}
          <div className="space-y-4">
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`relative rounded-lg border-2 border-dashed bg-card p-8 text-center transition-colors cursor-pointer ${
                dragOver ? "border-primary bg-primary/5" : "border-border hover:border-muted-foreground/30"
              }`}
              onClick={() => document.getElementById("image-input")?.click()}
            >
              <input
                id="image-input"
                type="file"
                accept="image/*"
                className="hidden"
                onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])}
              />

              {preview ? (
                <div className="space-y-4">
                  <img
                    src={preview}
                    alt="Preview"
                    className="max-h-64 mx-auto rounded-lg object-contain"
                  />
                  <div className="flex items-center justify-center gap-2">
                    <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); handleReset(); }} className="gap-1.5">
                      <RotateCcw className="w-3.5 h-3.5" /> Choose Different Image
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="py-8">
                  <Upload className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
                  <p className={`font-medium mb-1 ${seniorMode ? "text-xl" : "text-base"}`}>
                    {seniorMode ? "Click here to choose a photo" : "Drop an image or click to upload"}
                  </p>
                  <p className="text-xs text-muted-foreground">PNG, JPG, WebP supported</p>
                </div>
              )}
            </div>

            {result && (
              <div className="p-4 rounded-lg border border-border bg-card">
                <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">
                  Image Metadata
                </h3>
                <div className="space-y-2">
                  {Object.entries(result.metadata).map(([key, value]) => (
                    <div key={key} className="flex justify-between text-sm">
                      <span className="text-muted-foreground">{key}</span>
                      <span className="font-mono">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Results */}
          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center py-20 rounded-lg border border-border bg-card"
              >
                <Loader2 className="w-10 h-10 text-primary animate-spin mb-4" />
                <p className="text-muted-foreground text-sm">Analyzing image patterns...</p>
              </motion.div>
            ) : result ? (
              <motion.div
                key="result"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                className="space-y-4"
              >
                <div className="rounded-lg border border-border bg-card p-6 flex flex-col items-center">
                  <RiskGauge score={result.risk_score} classification={result.classification} />
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 }}
                    className={`mt-4 text-lg font-bold uppercase tracking-wider ${
                      result.classification === "Likely Authentic"
                        ? "text-success"
                        : result.classification === "Possibly AI-Generated"
                        ? "text-warning"
                        : "text-destructive"
                    }`}
                  >
                    {seniorMode
                      ? result.classification === "Likely Authentic"
                        ? "✅ This photo looks real"
                        : result.classification === "Possibly AI-Generated"
                        ? "⚠️ This might be computer-made"
                        : "🚨 This is probably fake!"
                      : result.classification
                    }
                  </motion.div>
                </div>

                {/* Indicators */}
                <div className="rounded-lg border border-border bg-card p-4 space-y-3">
                  <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                    Detection Indicators
                  </h3>
                  {result.indicators.map((ind, i) => (
                    <motion.div
                      key={i}
                      initial={{ opacity: 0, x: -10 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: i * 0.1 }}
                      className="flex items-start gap-2 text-sm"
                    >
                      <span className="mt-0.5">
                        {ind.includes("uncommon for AI") || ind.includes("EXIF metadata present") || ind.includes("suggests real")
                          ? "✅"
                          : "⚠️"
                        }
                      </span>
                      <span className="text-muted-foreground">{ind}</span>
                    </motion.div>
                  ))}
                </div>

                {/* Tips */}
                <div className="rounded-lg border border-primary/20 bg-primary/5 p-4">
                  <h3 className="text-sm font-semibold mb-2">💡 Tips</h3>
                  <ul className="space-y-1.5">
                    {result.tips.map((tip, i) => (
                      <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                        <span className="text-primary">•</span>
                        {tip}
                      </li>
                    ))}
                  </ul>
                  {file && (
                    <a
                      href={`https://lens.google.com/uploadbyurl?url=${encodeURIComponent(preview || "")}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1.5 mt-3 text-sm text-primary hover:underline"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      Try Google Reverse Image Search
                    </a>
                  )}
                </div>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-20 rounded-lg border border-dashed border-border bg-card/50"
              >
                <ImageIcon className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground text-sm">
                  {seniorMode ? "Upload a photo to check if it's real" : "Upload an image to analyze"}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

export default ImageAnalyzer;
