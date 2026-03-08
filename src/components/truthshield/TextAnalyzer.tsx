import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Send, Loader2, RotateCcw, FileText, Globe, BookOpen, Link2, TrendingUp } from "lucide-react";
import { analyzeText, type AnalysisResult } from "@/lib/analyzer";
import { addToHistory } from "./AnalysisHistory";
import { recordAnalysis } from "@/lib/analysisStore";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import RiskGauge from "./RiskGauge";
import SignalBars from "./SignalBars";
import ExplanationPanel from "./ExplanationPanel";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const SAMPLE_TEXTS = {
  scam: `Congratulations! You have been selected as a winner of our international lottery! Claim your prize of 5 million dollars now. Click here to verify your account immediately. This is a limited time offer — act now before it expires today! Wire transfer processing fee of $500 required. Contact our beneficiary department urgently.`,
  safe: `The quarterly report shows steady growth across all departments. Revenue increased by 12% compared to last quarter, driven primarily by expansion in the Southeast Asian market. The board has approved the new product roadmap for Q3 2026.`,
  ai: `In today's world, it's important to note that navigating the complexities of digital security has become multifaceted. Moreover, it is worth noting that leveraging comprehensive strategies can facilitate groundbreaking outcomes. Furthermore, harnessing the power of cutting-edge technology is crucial for fostering a paradigm shift in cybersecurity.`,
  indian: `Your SBI account has been temporarily blocked due to incomplete KYC update. Share your Aadhaar and PAN card details along with OTP to reactivate immediately. Your debit card blocked — call this number within 24 hours or face legal action. Income tax refund of ₹15,000 pending, share UPI details now.`,
};

const TextAnalyzer = () => {
  const [text, setText] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const { seniorMode } = useSeniorMode();

  const handleAnalyze = async () => {
    if (!text.trim()) return;
    setLoading(true);
    await new Promise(r => setTimeout(r, 800));
    const analysis = analyzeText(text);
    setResult(analysis);
    addToHistory("text", text, analysis.risk_score, analysis.classification);
    recordAnalysis({
      type: "text",
      input_preview: text.slice(0, 120),
      risk_score: analysis.risk_score,
      classification: analysis.classification,
      signals: analysis.signals,
    });
    setLoading(false);
  };

  const handleReset = () => {
    setText("");
    setResult(null);
  };

  const loadSample = (key: keyof typeof SAMPLE_TEXTS) => {
    setText(SAMPLE_TEXTS[key]);
    setResult(null);
  };

  return (
    <div className="min-h-screen">
      <div className="max-w-6xl mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className={`font-bold mb-2 ${seniorMode ? "text-3xl" : "text-2xl"}`}>
            <Shield className="w-6 h-6 inline-block mr-2 text-primary" />
            Text Analysis
          </h1>
          <p className={`text-muted-foreground ${seniorMode ? "text-lg" : "text-sm"}`}>
            Paste any text to analyze it for scam indicators, AI-generation patterns, and emotional manipulation.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-6">
          {/* Input Panel */}
          <div className="space-y-4">
            <div className="rounded-lg border border-border bg-card p-4">
              <Textarea
                placeholder={seniorMode
                  ? "Paste the suspicious text here... We'll check if it's safe for you."
                  : "Paste text to analyze for scam, AI, and manipulation patterns..."
                }
                value={text}
                onChange={e => setText(e.target.value)}
                className={`min-h-[200px] resize-none bg-transparent border-0 focus-visible:ring-0 p-0 ${seniorMode ? "text-lg" : ""}`}
              />
              <div className="flex items-center justify-between mt-3 pt-3 border-t border-border">
                <span className="text-xs text-muted-foreground font-mono">
                  {text.length} characters
                </span>
                <div className="flex gap-2">
                  {result && (
                    <Button variant="outline" size="sm" onClick={handleReset} className="gap-1.5">
                      <RotateCcw className="w-3.5 h-3.5" /> Reset
                    </Button>
                  )}
                  <Button
                    onClick={handleAnalyze}
                    disabled={!text.trim() || loading}
                    size="sm"
                    className="gap-1.5 bg-gradient-cyber hover:opacity-90 text-primary-foreground"
                  >
                    {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Send className="w-3.5 h-3.5" />}
                    {seniorMode ? "Check This Text" : "Analyze"}
                  </Button>
                </div>
              </div>
            </div>

            {/* Sample texts */}
            <div>
              <p className="text-xs text-muted-foreground mb-2 font-medium">Try a sample:</p>
              <div className="flex flex-wrap gap-2">
                {[
                  { key: "scam" as const, label: "🎣 Scam Email" },
                  { key: "safe" as const, label: "✅ Safe Text" },
                  { key: "ai" as const, label: "🤖 AI Generated" },
                  { key: "indian" as const, label: "🇮🇳 Indian Scam" },
                ].map(sample => (
                  <button
                    key={sample.key}
                    onClick={() => loadSample(sample.key)}
                    className="text-xs px-3 py-1.5 rounded-full border border-border bg-secondary hover:bg-secondary/80 transition-colors"
                  >
                    {sample.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Metadata cards (shown after analysis) */}
            {result && (
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-lg border border-border bg-card">
                  <div className="flex items-center gap-2 mb-1">
                    <Globe className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-medium text-muted-foreground">Language</span>
                  </div>
                  <p className="font-semibold text-sm">{result.language}</p>
                </div>
                <div className="p-3 rounded-lg border border-border bg-card">
                  <div className="flex items-center gap-2 mb-1">
                    <TrendingUp className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-medium text-muted-foreground">Confidence</span>
                  </div>
                  <p className="font-semibold text-sm">{result.confidence}%</p>
                </div>
                <div className="p-3 rounded-lg border border-border bg-card">
                  <div className="flex items-center gap-2 mb-1">
                    <BookOpen className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-medium text-muted-foreground">Readability</span>
                  </div>
                  <p className="font-semibold text-sm">{result.readability.level}</p>
                  <p className="text-xs text-muted-foreground">{result.readability.grade} • {result.readability.score}/100</p>
                </div>
                <div className="p-3 rounded-lg border border-border bg-card">
                  <div className="flex items-center gap-2 mb-1">
                    <FileText className="w-3.5 h-3.5 text-primary" />
                    <span className="text-xs font-medium text-muted-foreground">Word Count</span>
                  </div>
                  <p className="font-semibold text-sm">{result.readability.wordCount} words</p>
                  <p className="text-xs text-muted-foreground">{result.readability.sentenceCount} sentences • {result.readability.avgWordsPerSentence} avg</p>
                </div>
              </div>
            )}

            {/* URL analysis */}
            {result && result.url_analysis.length > 0 && (
              <div className="p-4 rounded-lg border border-border bg-card">
                <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
                  <Link2 className="w-4 h-4 text-primary" />
                  Links Found ({result.url_analysis.length})
                </h3>
                <div className="space-y-2">
                  {result.url_analysis.map((ua, i) => (
                    <div key={i} className={`p-2.5 rounded-md border text-sm ${
                      ua.safe ? "border-success/30 bg-success/5" : "border-destructive/30 bg-destructive/5"
                    }`}>
                      <div className="flex items-center justify-between mb-1">
                        <code className="text-xs break-all">{ua.url.length > 60 ? ua.url.slice(0, 57) + "..." : ua.url}</code>
                        <span className={`text-xs font-bold ml-2 ${ua.safe ? "text-success" : "text-destructive"}`}>
                          {ua.safe ? "✅ Safe" : `⚠️ ${ua.score}/100`}
                        </span>
                      </div>
                      {ua.flags.map((f, j) => (
                        <p key={j} className="text-xs text-muted-foreground pl-2">• {f}</p>
                      ))}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Results Panel */}
          <AnimatePresence mode="wait">
            {loading ? (
              <motion.div
                key="loading"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                exit={{ opacity: 0 }}
                className="flex flex-col items-center justify-center py-20 rounded-lg border border-border bg-card"
              >
                <div className="relative">
                  <div className="w-20 h-20 rounded-full border-4 border-border animate-pulse" />
                  <Loader2 className="w-8 h-8 text-primary absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 animate-spin" />
                </div>
                <p className="mt-4 text-muted-foreground text-sm">
                  {seniorMode ? "Checking the text for you..." : "Running multi-factor analysis..."}
                </p>
              </motion.div>
            ) : result ? (
              <motion.div
                key="result"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -20 }}
                className="space-y-4"
              >
                <div className="rounded-lg border border-border bg-card p-6 flex flex-col items-center">
                  <RiskGauge score={result.risk_score} classification={result.classification} />
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.5 }}
                    className={`mt-4 text-lg font-bold uppercase tracking-wider ${
                      result.classification === "Safe"
                        ? "text-success"
                        : result.classification === "Suspicious"
                        ? "text-warning"
                        : "text-destructive"
                    }`}
                  >
                    {seniorMode
                      ? result.classification === "Safe"
                        ? "✅ This looks safe"
                        : result.classification === "Suspicious"
                        ? "⚠️ Be careful with this"
                        : "🚨 This is dangerous!"
                      : result.classification
                    }
                  </motion.div>
                </div>

                <Tabs defaultValue="signals" className="rounded-lg border border-border bg-card">
                  <TabsList className="w-full bg-secondary/50 rounded-t-lg rounded-b-none">
                    <TabsTrigger value="signals" className="flex-1">Signals</TabsTrigger>
                    <TabsTrigger value="explain" className="flex-1">
                      {seniorMode ? "Why?" : "Explanations"}
                    </TabsTrigger>
                    <TabsTrigger value="highlighted" className="flex-1">Highlighted</TabsTrigger>
                  </TabsList>

                  <div className="p-4">
                    <TabsContent value="signals">
                      <SignalBars signals={result.signals} />
                    </TabsContent>

                    <TabsContent value="explain">
                      <ExplanationPanel
                        explanations={result.explanations}
                        summary={result.summary}
                        tips={result.tips}
                      />
                    </TabsContent>

                    <TabsContent value="highlighted">
                      <div className="space-y-3">
                        <p className="text-xs text-muted-foreground">
                          Suspicious phrases are <mark className="bg-destructive/20 text-destructive px-1 rounded">highlighted</mark> below:
                        </p>
                        <div
                          className={`p-4 rounded-lg bg-secondary/30 leading-relaxed ${seniorMode ? "text-base" : "text-sm"}`}
                          dangerouslySetInnerHTML={{
                            __html: result.highlighted_text.replace(
                              /<mark>/g,
                              '<mark class="bg-destructive/20 text-destructive px-1 rounded">'
                            ),
                          }}
                        />
                      </div>
                    </TabsContent>
                  </div>
                </Tabs>
              </motion.div>
            ) : (
              <motion.div
                key="empty"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex flex-col items-center justify-center py-20 rounded-lg border border-dashed border-border bg-card/50"
              >
                <FileText className="w-12 h-12 text-muted-foreground/30 mb-4" />
                <p className="text-muted-foreground text-sm">
                  {seniorMode ? "Paste some text and click 'Check This Text'" : "Paste text and click Analyze to see results"}
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </div>
    </div>
  );
};

export default TextAnalyzer;
