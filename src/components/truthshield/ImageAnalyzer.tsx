import { useState, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { ImageIcon, Upload, Loader2, RotateCcw, FileSearch, ScanText, Search, ShieldAlert, Link as LinkIcon } from "lucide-react";
import { extractTextFromImage } from "@/lib/ocr";
import { analyzeText, analyzeURL, type AnalysisResult, type URLAnalysisResult } from "@/lib/analyzer";
import { addToHistory } from "./AnalysisHistory";
import { recordAnalysis } from "@/lib/analysisStore";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import RiskGauge from "./RiskGauge";
import OCRAnalysisPanel, { type OCRResultData } from "./OCRAnalysisPanel";
import ReverseImageSearchPanel, { type ReverseSearchData } from "./ReverseImageSearchPanel";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const API_BASE = "https://truth-guard-1.onrender.com";

type ScreenshotResult = OCRResultData & {
  links?: string[];
  urlAnalysis?: URLAnalysisResult[];
  ocrProvider?: string;
};

const mapAnalysisToOcr = (
  extractedText: string,
  confidence: number,
  analysis: AnalysisResult,
  links: string[] = [],
  provider = "browser:tesseract"
): ScreenshotResult => ({
  loading: false,
  hasText: extractedText.trim().length > 0,
  extractedText,
  confidence,
  riskScore: analysis.risk_score,
  classification: analysis.classification,
  scamType: analysis.signals.scam_keywords > 40 ? "Screenshot Scam / Phishing" : analysis.signals.ai_generated > 50 ? "AI Text" : "Safe",
  emotionalManipulation: analysis.signals.emotional_manipulation > 35,
  signals: analysis.signals,
  suspiciousPhrases: analysis.suspicious_phrases,
  summary: analysis.summary,
  tips: analysis.tips,
  links,
  urlAnalysis: analysis.url_analysis,
  ocrProvider: provider,
});

const ImageAnalyzer = () => {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [screenshotResult, setScreenshotResult] = useState<ScreenshotResult>({ loading: false, hasText: false, extractedText: "" });
  const [reverseResult, setReverseResult] = useState<ReverseSearchData>({ loading: false });
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState("screenshot");
  const [dragOver, setDragOver] = useState(false);
  const { seniorMode } = useSeniorMode();

  const analyzeScreenshot = async (f: File): Promise<ScreenshotResult> => {
    const form = new FormData();
    form.append("file", f);

    try {
      const serverRes = await fetch(`${API_BASE}/api/image/analyze-screenshot`, { method: "POST", body: form });
      if (serverRes.ok) {
        const d = await serverRes.json();
        return {
          loading: false,
          hasText: !!d.hasText,
          extractedText: d.extractedText || "",
          confidence: d.ocrConfidence || 0,
          riskScore: d.riskScore,
          classification: d.classification,
          scamType: d.scamType,
          emotionalManipulation: d.emotionalManipulation,
          signals: d.signals,
          suspiciousPhrases: d.suspiciousPhrases,
          summary: d.summary,
          tips: d.tips,
          links: d.links || [],
          urlAnalysis: (d.links || []).map((url: string) => analyzeURL(url)),
          ocrProvider: d.ocrProvider,
        };
      }
    } catch {
      // Deployed backend may not yet have the new OCR endpoint; use browser OCR fallback.
    }

    const ocr = await extractTextFromImage(f);
    const extractedText = ocr.text.trim();
    if (!extractedText) {
      return {
        loading: false,
        hasText: false,
        extractedText: "",
        confidence: ocr.confidence,
        error: "No readable text found. Try a sharper screenshot or crop around the message.",
      };
    }

    const analysis = analyzeText(extractedText);
    return mapAnalysisToOcr(extractedText, ocr.confidence, analysis, analysis.url_analysis.map(u => u.url));
  };

  const runReverseSearch = async (f: File, previewUrl: string) => {
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
  };

  const handleFile = useCallback(async (f: File) => {
    if (!f.type.startsWith("image/")) return;
    const objectUrl = URL.createObjectURL(f);
    setFile(f);
    setPreview(objectUrl);
    setScreenshotResult({ loading: true, hasText: false, extractedText: "" });
    setReverseResult({ loading: true, previewUrl: objectUrl });
    setLoading(true);
    setActiveTab("screenshot");

    runReverseSearch(f, objectUrl);
    const result = await analyzeScreenshot(f);
    setScreenshotResult(result);

    const score = result.riskScore ?? (result.hasText ? 25 : 0);
    const classification = result.classification ?? (result.hasText ? "Suspicious" : "No Text");
    addToHistory("image", f.name, score, classification);
    recordAnalysis({
      type: "image",
      input_preview: result.extractedText ? result.extractedText.slice(0, 120) : f.name,
      risk_score: score,
      classification,
      signals: result.signals || { ai_generated: 0, scam_keywords: score, emotional_manipulation: 0 },
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
    if (preview) URL.revokeObjectURL(preview);
    setFile(null);
    setPreview(null);
    setScreenshotResult({ loading: false, hasText: false, extractedText: "" });
    setReverseResult({ loading: false });
    setActiveTab("screenshot");
    setLoading(false);
  };

  const riskScore = screenshotResult.riskScore ?? reverseResult.riskScore ?? 0;
  const classification = screenshotResult.classification ?? (reverseResult.found ? "Suspicious" : "Safe");

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className={`font-bold mb-2 ${seniorMode ? "text-3xl" : "text-2xl"}`}>
            <ImageIcon className="w-6 h-6 inline-block mr-2 text-primary" />
            Screenshot & Image Source Check
          </h1>
          <p className={`text-muted-foreground ${seniorMode ? "text-lg" : "text-sm"}`}>
            {seniorMode
              ? "Upload a screenshot. TruthShield reads the text, checks links, and tells you if it may be a scam."
              : "OCR screenshot scam analysis plus perceptual reverse-search for source/reuse clues — no AI-image authenticity scoring."}
          </p>
        </div>

        <div className="grid lg:grid-cols-5 gap-6">
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
                  <img src={preview} alt="Uploaded screenshot preview" className="max-h-56 mx-auto rounded-lg object-contain shadow-lg" />
                  <Button variant="outline" size="sm" onClick={(e) => { e.stopPropagation(); handleReset(); }} className="gap-1.5">
                    <RotateCcw className="w-3.5 h-3.5" /> New Image
                  </Button>
                </div>
              ) : (
                <div className="py-6">
                  <Upload className="w-12 h-12 mx-auto mb-4 text-muted-foreground/40" />
                  <p className={`font-medium mb-1 ${seniorMode ? "text-xl" : "text-base"}`}>
                    {seniorMode ? "Click here to choose a screenshot" : "Drop a screenshot/image or click to upload"}
                  </p>
                  <p className="text-xs text-muted-foreground">PNG, JPG, WebP supported (max 20MB)</p>
                </div>
              )}
            </div>

            {file && !loading && (
              <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="rounded-xl border border-border bg-card p-4">
                <RiskGauge score={riskScore} classification={classification} />
                <div className={`mt-3 text-center text-sm font-bold uppercase tracking-wider ${
                  riskScore <= 30 ? "text-emerald-400" : riskScore <= 60 ? "text-yellow-400" : "text-red-400"
                }`}>
                  {seniorMode
                    ? riskScore <= 30 ? "✅ Looks okay" : riskScore <= 60 ? "⚠️ Be careful" : "🚨 High scam risk"
                    : classification}
                </div>
                <p className="text-center text-xs text-muted-foreground mt-2">
                  Score is based on extracted text, links, and known-image reuse signals.
                </p>
              </motion.div>
            )}
          </div>

          <div className="lg:col-span-3">
            <AnimatePresence mode="wait">
              {loading ? (
                <motion.div key="loading" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="flex flex-col items-center justify-center py-20 rounded-xl border border-border bg-card">
                  <Loader2 className="w-10 h-10 text-primary animate-spin mb-4" />
                  <p className="text-muted-foreground text-sm">Reading screenshot and checking image source…</p>
                  <p className="text-muted-foreground/60 text-xs mt-1">OCR + link analysis + reverse-search</p>
                </motion.div>
              ) : file ? (
                <motion.div key="results" initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }}>
                  <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                    <TabsList className="grid w-full grid-cols-3 mb-4">
                      <TabsTrigger value="screenshot" className="gap-1 text-[11px]">
                        <ScanText className="w-3.5 h-3.5" /> {seniorMode ? "Text" : "Screenshot OCR"}
                      </TabsTrigger>
                      <TabsTrigger value="links" className="gap-1 text-[11px]">
                        <LinkIcon className="w-3.5 h-3.5" /> Links
                      </TabsTrigger>
                      <TabsTrigger value="reverse" className="gap-1 text-[11px]">
                        <Search className="w-3.5 h-3.5" /> {seniorMode ? "Source" : "Reverse Search"}
                      </TabsTrigger>
                    </TabsList>

                    <TabsContent value="screenshot">
                      <OCRAnalysisPanel data={screenshotResult} />
                    </TabsContent>

                    <TabsContent value="links">
                      <div className="rounded-xl border border-border bg-card p-4 space-y-3">
                        <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
                          <LinkIcon className="w-3.5 h-3.5" /> Links found in screenshot
                        </h3>
                        {screenshotResult.urlAnalysis && screenshotResult.urlAnalysis.length > 0 ? (
                          screenshotResult.urlAnalysis.map((u, i) => (
                            <div key={i} className={`rounded-lg border p-3 ${u.safe ? "border-emerald-500/30 bg-emerald-500/5" : "border-red-500/30 bg-red-500/5"}`}>
                              <div className="font-mono text-xs break-all text-primary">{u.url}</div>
                              <div className="mt-2 text-sm font-semibold">{u.classification} · {u.score}/100</div>
                              {u.flags.length > 0 && <ul className="mt-2 text-xs text-muted-foreground space-y-1">{u.flags.map((flag, idx) => <li key={idx}>• {flag}</li>)}</ul>}
                            </div>
                          ))
                        ) : (
                          <p className="text-sm text-muted-foreground">No links were detected in the screenshot text.</p>
                        )}
                      </div>
                    </TabsContent>

                    <TabsContent value="reverse">
                      <ReverseImageSearchPanel data={reverseResult} />
                    </TabsContent>
                  </Tabs>
                </motion.div>
              ) : (
                <motion.div key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex flex-col items-center justify-center py-20 rounded-xl border border-dashed border-border bg-card/50">
                  <ImageIcon className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground text-sm">
                    {seniorMode ? "Upload a screenshot to check it" : "Upload a screenshot or web image to analyze"}
                  </p>
                  <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                    <div className="p-3 rounded-lg bg-muted/30">
                      <ScanText className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">OCR</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/30">
                      <ShieldAlert className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">Scam Risk</p>
                    </div>
                    <div className="p-3 rounded-lg bg-muted/30">
                      <FileSearch className="w-5 h-5 mx-auto mb-1 text-muted-foreground/50" />
                      <p className="text-xs text-muted-foreground">Source</p>
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
