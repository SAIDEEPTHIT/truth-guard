import { motion } from "framer-motion";
import { FileText, AlertTriangle, ShieldCheck, Loader2, ScanText, Sparkles } from "lucide-react";

export interface OCRResultData {
  loading: boolean;
  hasText: boolean;
  extractedText: string;
  confidence?: number;
  riskScore?: number;
  classification?: string;
  scamType?: string;
  emotionalManipulation?: boolean;
  signals?: { ai_generated: number; scam_keywords: number; emotional_manipulation: number };
  suspiciousPhrases?: string[];
  summary?: string;
  tips?: string[];
  error?: string;
}

interface Props {
  data: OCRResultData;
}

const tone = (score: number) =>
  score <= 30
    ? { ring: "border-emerald-500/40", bg: "bg-emerald-500/10", text: "text-emerald-400", chip: "bg-emerald-500/20 text-emerald-300" }
    : score <= 60
    ? { ring: "border-yellow-500/40", bg: "bg-yellow-500/10", text: "text-yellow-400", chip: "bg-yellow-500/20 text-yellow-300" }
    : { ring: "border-red-500/40", bg: "bg-red-500/10", text: "text-red-400", chip: "bg-red-500/20 text-red-300" };

const OCRAnalysisPanel = ({ data }: Props) => {
  if (data.loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16 rounded-xl border border-border bg-card">
        <Loader2 className="w-8 h-8 text-primary animate-spin mb-3" />
        <p className="text-sm text-muted-foreground">Extracting text from image…</p>
        <p className="text-xs text-muted-foreground/60 mt-1">OCR running in your browser (offline, private)</p>
      </div>
    );
  }

  if (!data.hasText) {
    return (
      <div className="rounded-xl border border-border bg-card p-6 text-center">
        <ScanText className="w-10 h-10 text-muted-foreground/40 mx-auto mb-3" />
        <h3 className="font-semibold mb-1">No readable text found</h3>
        <p className="text-sm text-muted-foreground">
          We couldn't extract text from this image. If you expected text, try a sharper or higher-resolution image.
        </p>
        {data.error && <p className="text-xs text-red-400 mt-3">{data.error}</p>}
      </div>
    );
  }

  const score = data.riskScore ?? 0;
  const t = tone(score);

  return (
    <div className="space-y-4">
      {/* Extracted text */}
      <div className="rounded-xl border border-border bg-card p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <FileText className="w-3.5 h-3.5" /> Text Found in Image
          </h3>
          {typeof data.confidence === "number" && (
            <span className="text-[10px] font-mono text-muted-foreground">
              OCR confidence {data.confidence}%
            </span>
          )}
        </div>
        <pre className="whitespace-pre-wrap font-mono text-xs leading-relaxed bg-background/50 rounded-md p-3 max-h-48 overflow-auto">
{data.extractedText}
        </pre>
      </div>

      {/* Verdict */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl border ${t.ring} ${t.bg} p-4`}
      >
        <div className="flex items-start justify-between gap-3">
          <div>
            <div className={`text-xs font-bold uppercase tracking-wider ${t.text}`}>
              {data.classification ?? "Analyzed"}
            </div>
            <div className="mt-1 text-sm">
              <span className="font-semibold">Scam type:</span> {data.scamType ?? "—"}
            </div>
            {data.emotionalManipulation && (
              <div className="mt-1 inline-flex items-center gap-1 text-xs text-yellow-300">
                <AlertTriangle className="w-3 h-3" /> Emotional manipulation detected
              </div>
            )}
          </div>
          <div className={`text-3xl font-bold font-mono ${t.text}`}>{score}</div>
        </div>
        {data.summary && (
          <p className="mt-3 text-sm text-muted-foreground leading-relaxed">{data.summary}</p>
        )}
      </motion.div>

      {/* Suspicious phrases */}
      {data.suspiciousPhrases && data.suspiciousPhrases.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-2">
            <Sparkles className="w-3.5 h-3.5" /> Suspicious phrases
          </h3>
          <div className="flex flex-wrap gap-1.5">
            {data.suspiciousPhrases.map((p, i) => (
              <span key={i} className={`text-xs px-2 py-1 rounded-md ${t.chip}`}>{p}</span>
            ))}
          </div>
        </div>
      )}

      {/* Signals */}
      {data.signals && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Signals</h3>
          {(["scam_keywords", "emotional_manipulation", "ai_generated"] as const).map(k => (
            <div key={k}>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-muted-foreground capitalize">{k.replace("_", " ")}</span>
                <span className="font-mono">{data.signals![k]}%</span>
              </div>
              <div className="h-1.5 rounded-full bg-background overflow-hidden">
                <div
                  className={`h-full ${
                    data.signals![k] > 60 ? "bg-red-500" : data.signals![k] > 30 ? "bg-yellow-500" : "bg-emerald-500"
                  }`}
                  style={{ width: `${data.signals![k]}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Tips */}
      {data.tips && data.tips.length > 0 && (
        <div className="rounded-xl border border-primary/20 bg-primary/5 p-4">
          <h3 className="text-sm font-semibold mb-2 flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-primary" /> Recommendations
          </h3>
          <ul className="space-y-1.5">
            {data.tips.map((tip, i) => (
              <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                <span className="text-primary">•</span>{tip}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
};

export default OCRAnalysisPanel;
