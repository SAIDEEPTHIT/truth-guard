import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ImageIcon, Upload, Loader2, RotateCcw, ExternalLink, Scan, FileSearch, ShieldAlert, BarChart3, ScanText, Search } from "lucide-react";
import { analyzeImage, type ImageAnalysisResult } from "@/lib/analyzer";
import { extractTextFromImage } from "@/lib/ocr";
import { addToHistory } from "./AnalysisHistory";
import { recordAnalysis } from "@/lib/analysisStore";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import RiskGauge from "./RiskGauge";
import ImageMetadataPanel from "./ImageMetadataPanel";
import AIDetectionPanel from "./AIDetectionPanel";
import ImageRiskIndicators from "./ImageRiskIndicators";
import OCRAnalysisPanel, { type OCRResultData } from "./OCRAnalysisPanel";
import ReverseImageSearchPanel, { type ReverseSearchData } from "./ReverseImageSearchPanel";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const API_BASE = "https://truth-guard-1.onrender.com";

interface EnhancedResult {
  riskScore: number;
  classification: string;
  metadata: Record<string, unknown>;
  metadataScore: number;
  metadataIndicators: Array<{ signal: string; detail: string; severity: string; type: string }>;
  pixelAnalysis: {
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
  };
  aiDetection: { score: number; model: string; available: boolean };
  flags: Array<{ flag: string; label: string; severity: string; detail: string }>;
  recommendation: { level: string; title: string; message: string; icon: string; color: string };
  confidence: number;
  scoreBreakdown: {
    metadata: number;
    pixelAnalysis: number;
    aiModel: number | null;
    weights: { metadata: number; pixelAnalysis: number; aiModel: number };
  };
  tips: string[];
  allIndicators: Array<{ signal: string; detail: string; severity: string; type: string }>;
}

const ImageAnalyzer = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [localResult, setLocalResult] = useState<ImageAnalysisResult | null>(null);
  const [enhancedResult, setEnhancedResult] = useState<EnhancedResult | null>(null);
  const [ocrResult, setOcrResult] = useState<OCRResultData>({ loading: false, hasText: false, extractedText: "" });
  const [reverseResult, setReverseResult] = useState<ReverseSearchData>({ loading: false });
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("overview");
  const [dragOver, setDragOver] = useState(false);
  const [analysisMode, setAnalysisMode] = useState<"local" | "enhanced">("local");
  const { seniorMode } = useSeniorMode();

  const handleFile = useCallback(async (f: File) => {
    if (!f.type.startsWith("image/")) return;
    setFile(f);
    setPreview(URL.createObjectURL(f));
    setLocalResult(null);
    setEnhancedResult(null);
    setOcrResult({ loading: true, hasText: false, extractedText: "" });
    setReverseResult({ loading: true });
    setLoading(true);
    setActiveTab("overview");

    // Kick off OCR (browser-side, free) and reverse-search in parallel — they don't block UI
    const previewUrl = URL.createObjectURL(f);
    (async () => {
      try {
        const ocr = await extractTextFromImage(f);
        if (!ocr.text) {
          setOcrResult({ loading: false, hasText: false, extractedText: "", confidence: ocr.confidence });
          return;
        }
        // Send extracted text to backend scam analyzer
        const res = await fetch(`${API_BASE}/api/image/analyze-ocr`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ text: ocr.text, filename: f.name }),
        });
        if (res.ok) {
          const d = await res.json();
          setOcrResult({
            loading: false,
            hasText: !!d.hasText,
            extractedText: d.extractedText || ocr.text,
            confidence: ocr.confidence,
            riskScore: d.riskScore,
            classification: d.classification,
            scamType: d.scamType,
            emotionalManipulation: d.emotionalManipulation,
            signals: d.signals,
            suspiciousPhrases: d.suspiciousPhrases,
            summary: d.summary,
            tips: d.tips,
          });
        } else {
          setOcrResult({ loading: false, hasText: true, extractedText: ocr.text, confidence: ocr.confidence, error: "Backend scam analyzer unavailable" });
        }
      } catch (err) {
        setOcrResult({ loading: false, hasText: false, extractedText: "", error: String(err) });
      }
    })();

    (async () => {
      try {
        const form = new FormData();
        form.append("file", f);
        const res = await fetch(`${API_BASE}/api/image/reverse-search`, { method: "POST", body: form });
        if (res.ok) {
          const d = await res.json();
          setReverseResult({ loading: false, ...d, previewUrl });
        } else {
          setReverseResult({ loading: false, error: `HTTP ${res.status}`, previewUrl });
        }
      } catch (err) {
        setReverseResult({ loading: false, error: String(err), previewUrl });
      }
    })();

    // Run local analysis immediately
    const localAnalysis = await analyzeImage(f);
    setLocalResult(localAnalysis);
    setAnalysisMode("local");

    // Try enhanced backend analysis
    try {
      const formData = new FormData();
      formData.append("file", f);
      const response = await fetch(`${API_BASE}/api/image/analyze-full`, {
        method: "POST",
        body: formData,
      });
      if (response.ok) {
        const data = await response.json();
        setEnhancedResult(data);
        setAnalysisMode("enhanced");
        addToHistory("image", f.name, data.riskScore, data.classification);
        recordAnalysis({
          type: "image",
          input_preview: f.name,
          risk_score: data.riskScore,
          classification: data.classification,
          signals: { ai_generated: data.aiDetection?.score || 0, scam_keywords: 0, emotional_manipulation: 0 },
        });
      } else {
        // Fallback to local
        addToHistory("image", f.name, localAnalysis.risk_score, localAnalysis.classification);
        recordAnalysis({
          type: "image",
          input_preview: f.name,
          risk_score: localAnalysis.risk_score,
          classification: localAnalysis.classification,
          signals: { ai_generated: localAnalysis.risk_score, scam_keywords: 0, emotional_manipulation: 0 },
        });
      }
    } catch {
      addToHistory("image", f.name, localAnalysis.risk_score, localAnalysis.classification);
      recordAnalysis({
        type: "image",
        input_preview: f.name,
        risk_score: localAnalysis.risk_score,
        classification: localAnalysis.classification,
        signals: { ai_generated: localAnalysis.risk_score, scam_keywords: 0, emotional_manipulation: 0 },
      });
    }

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
    setLocalResult(null);
    setEnhancedResult(null);
    setActiveTab("overview");
  };

  const riskScore = enhancedResult ? enhancedResult.riskScore : localResult?.risk_score ?? 0;
  const classification = enhancedResult ? enhancedResult.classification : localResult?.classification ?? "";

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className={`font-bold mb-2 ${seniorMode ? "text-3xl" : "text-2xl"}`}>
            <ImageIcon className="w-6 h-6 inline-block mr-2 text-primary" />
            AI Image Detection
          </h1>
          <p className={`text-muted-foreground ${seniorMode ? "text-lg" : "text-sm"}`}>
            {seniorMode
              ? "Upload a photo to check if it was made by a computer (AI)"
              : "Advanced AI-powered image authenticity analysis with metadata, pixel patterns, and ML detection"
            }
          </p>
        </div>

        <div className="grid lg:grid-cols-5 gap-6">
          {/* Upload area - 2 cols */}
          <div className="lg:col-span-2 space-y-4">
            <div
              onDragOver={e => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
              className={`relative rounded-xl border-2 border-dashed bg-card p-6 text-center transition-all cursor-pointer ${
                dragOver ? "border-primary bg-primary/5 scale-[1.02]" : "border-border hover:border-muted-foreground/30"
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
                <div className="space-y-3">
                  <img
                    src={preview}
                    alt="Preview"
                    className="max-h-56 mx-auto rounded-lg object-contain shadow-lg"
                  />
                  <div className="flex items-center justify-center gap-2">
                    <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); handleReset(); }} className="gap-1.5">
                      <RotateCcw className="w-3.5 h-3.5" /> New Image
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="py-6">
                  <Upload className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
                  <p className={`font-medium mb-1 ${seniorMode ? "text-xl" : "text-base"}`}>
                    {seniorMode ? "Click here to choose a photo" : "Drop an image or click to upload"}
                  </p>
                  <p className="text-xs text-muted-foreground">PNG, JPG, WebP supported (max 20MB)</p>
                </div>
              )}
            </div>

            {/* Quick score display */}
            {(localResult || enhancedResult) && !loading && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="rounded-xl border border-border bg-card p-4"
              >
                <RiskGauge score={riskScore} classification={classification} />
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.5 }}
                  className={`mt-3 text-center text-sm font-bold uppercase tracking-wider ${
                    riskScore <= 30 ? "text-emerald-400" : riskScore <= 60 ? "text-yellow-400" : "text-red-400"
                  }`}
                >
                  {seniorMode
                    ? riskScore <= 30 ? "✅ Looks real!" : riskScore <= 60 ? "⚠️ Not sure" : "🚨 Probably fake!"
                    : classification
                  }
                </motion.div>
                {analysisMode === "enhanced" && (
                  <p className="text-center text-xs text-primary mt-2">
                    🔬 Enhanced analysis (HuggingFace + Pixel + Metadata)
                  </p>
                )}
                {analysisMode === "local" && (
                  <p className="text-center text-xs text-muted-foreground mt-2">
                    Local heuristic analysis
                  </p>
                )}
              </motion.div>
            )}

            {/* Quick metadata */}
            {localResult && !enhancedResult && (
              <div className="p-4 rounded-xl border border-border bg-card">
                <h3 className="text-xs font-semibold mb-3 text-muted-foreground uppercase tracking-wider">File Info</h3>
                <div className="space-y-2">
                  {Object.entries(localResult.metadata).map(([key, value]) => (
                    <div key={key} className="flex justify-between text-sm">
                      <span className="text-muted-foreground">{key}</span>
                      <span className="font-mono text-xs">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Results - 3 cols */}
          <div className="lg:col-span-3">
            <AnimatePresence mode="wait">
              {loading ? (
                <motion.div
                  key="loading"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex flex-col items-center justify-center py-20 rounded-xl border border-border bg-card"
                >
                  <Loader2 className="w-10 h-10 text-primary animate-spin mb-4" />
                  <p className="text-muted-foreground text-sm">Analyzing image patterns...</p>
                  <p className="text-muted-foreground/60 text-xs mt-1">Running metadata, pixel, and AI detection</p>
                </motion.div>
              ) : enhancedResult ? (
                <motion.div
                  key="enhanced"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                >
                  <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                    <TabsList className="grid w-full grid-cols-4 mb-4">
                      <TabsTrigger value="overview" className="gap-1 text-xs">
                        <ShieldAlert className="w-3.5 h-3.5" />
                        {seniorMode ? "Result" : "Risk"}
                      </TabsTrigger>
                      <TabsTrigger value="metadata" className="gap-1 text-xs">
                        <FileSearch className="w-3.5 h-3.5" />
                        {seniorMode ? "Details" : "Metadata"}
                      </TabsTrigger>
                      <TabsTrigger value="ai" className="gap-1 text-xs">
                        <Scan className="w-3.5 h-3.5" />
                        {seniorMode ? "AI Check" : "AI Detection"}
                      </TabsTrigger>
                      <TabsTrigger value="breakdown" className="gap-1 text-xs">
                        <BarChart3 className="w-3.5 h-3.5" />
                        {seniorMode ? "Score" : "Breakdown"}
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="overview">
                      <ImageRiskIndicators
                        riskScore={enhancedResult.riskScore}
                        classification={enhancedResult.classification}
                        confidence={enhancedResult.confidence}
                        flags={enhancedResult.flags}
                        recommendation={enhancedResult.recommendation}
                        scoreBreakdown={enhancedResult.scoreBreakdown}
                        tips={enhancedResult.tips}
                        fullResult={enhancedResult as unknown as Record<string, unknown>}
                      />
                    </TabsContent>

                    <TabsContent value="metadata">
                      <ImageMetadataPanel
                        metadata={enhancedResult.metadata as any}
                        metadataScore={enhancedResult.metadataScore}
                        indicators={enhancedResult.metadataIndicators}
                      />
                    </TabsContent>

                    <TabsContent value="ai">
                      <AIDetectionPanel
                        pixelAnalysis={enhancedResult.pixelAnalysis}
                        aiDetection={enhancedResult.aiDetection}
                      />
                    </TabsContent>

                    <TabsContent value="breakdown">
                      <ImageRiskIndicators
                        riskScore={enhancedResult.riskScore}
                        classification={enhancedResult.classification}
                        confidence={enhancedResult.confidence}
                        flags={enhancedResult.flags}
                        recommendation={enhancedResult.recommendation}
                        scoreBreakdown={enhancedResult.scoreBreakdown}
                        tips={enhancedResult.tips}
                        fullResult={enhancedResult as unknown as Record<string, unknown>}
                      />
                    </TabsContent>
                  </Tabs>
                </motion.div>
              ) : localResult ? (
                <motion.div
                  key="local"
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="space-y-4"
                >
                  <div className="rounded-xl border border-border bg-card p-6 flex flex-col items-center">
                    <RiskGauge score={localResult.risk_score} classification={localResult.classification} />
                    <motion.div
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.5 }}
                      className={`mt-4 text-lg font-bold uppercase tracking-wider ${
                        localResult.classification === "Likely Authentic"
                          ? "text-emerald-400"
                          : localResult.classification === "Possibly AI-Generated"
                          ? "text-yellow-400"
                          : "text-red-400"
                      }`}
                    >
                      {seniorMode
                        ? localResult.classification === "Likely Authentic"
                          ? "✅ This photo looks real"
                          : localResult.classification === "Possibly AI-Generated"
                          ? "⚠️ This might be computer-made"
                          : "🚨 This is probably fake!"
                        : localResult.classification
                      }
                    </motion.div>
                    <p className="text-xs text-muted-foreground mt-2">
                      Local analysis only — backend unavailable
                    </p>
                  </div>

                  {/* Indicators */}
                  <div className="rounded-xl border border-border bg-card p-4 space-y-3">
                    <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                      Detection Indicators
                    </h3>
                    {localResult.indicators.map((ind, i) => (
                      <motion.div
                        key={i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        transition={{ delay: i * 0.05 }}
                        className="flex items-start gap-2 text-sm"
                      >
                        <span className="mt-0.5">
                          {ind.includes("✅") ? "✅" : "⚠️"}
                        </span>
                        <span className="text-muted-foreground">{ind}</span>
                      </motion.div>
                    ))}
                  </div>

                  {/* Tips */}
                  <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
                    <h3 className="text-sm font-semibold mb-2">💡 Tips</h3>
                    <ul className="space-y-1.5">
                      {localResult.tips.map((tip, i) => (
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
                  className="flex flex-col items-center justify-center py-20 rounded-xl border border-dashed border-border bg-card/50"
                >
                  <ImageIcon className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground text-sm">
                    {seniorMode ? "Upload a photo to check if it's real" : "Upload an image to analyze"}
                  </p>
                  <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                    <div className="p-3 rounded-lg bg-muted/30">
                      <FileSearch className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">Metadata</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/30">
                      <Scan className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">Pixel AI</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/30">
                      <ShieldAlert className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">Risk Score</p>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ImageAnalyzer;
