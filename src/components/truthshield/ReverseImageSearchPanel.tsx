import { motion } from "framer-motion";
import { Search, ExternalLink, ShieldAlert, Loader2, Fingerprint } from "lucide-react";

export interface ReverseSearchSource {
  url: string;
  title: string;
  category: string;
  first_seen?: string;
  reports?: number;
  matched_hash?: string;
  distance?: number;
  confidence?: number;
  isSuspicious?: boolean;
}

export interface ReverseSearchData {
  loading: boolean;
  imageHash?: string;
  hashAlgorithm?: string;
  found?: boolean;
  matchCount?: number;
  sources?: ReverseSearchSource[];
  riskIndicators?: string[];
  riskScore?: number;
  databaseSize?: number;
  previewUrl?: string;
  error?: string;
}

const tone = (score: number) =>
  score <= 30
    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
    : score <= 60
    ? "border-yellow-500/40 bg-yellow-500/10 text-yellow-400"
    : "border-red-500/40 bg-red-500/10 text-red-400";

const ReverseImageSearchPanel = ({ data }: { data: ReverseSearchData }) => {
  if (data.loading) {
    return (
      <div className="flex flex-col items-center justify-center py-16 rounded-xl border border-border bg-card">
        <Loader2 className="w-8 h-8 text-primary animate-spin mb-3" />
        <p className="text-sm text-muted-foreground">Computing perceptual hash & searching…</p>
      </div>
    );
  }

  if (data.error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-4 text-sm text-red-300">
        Reverse search unavailable: {data.error}
      </div>
    );
  }

  const score = data.riskScore ?? 0;

  return (
    <div className="space-y-4">
      {/* Hash card */}
      <div className="rounded-xl border border-border bg-card p-4">
        <div className="flex items-center justify-between mb-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-2">
            <Fingerprint className="w-3.5 h-3.5" /> Perceptual Fingerprint
          </h3>
          <span className="text-[10px] font-mono text-muted-foreground">{data.hashAlgorithm}</span>
        </div>
        <code className="block font-mono text-xs break-all bg-background/50 rounded-md p-3 text-primary">
          {data.imageHash || "—"}
        </code>
        {typeof data.databaseSize === "number" && (
          <p className="text-[11px] text-muted-foreground mt-2">
            Compared against {data.databaseSize} known phishing/scam image fingerprints.
          </p>
        )}
      </div>

      {/* Verdict */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl border p-4 ${tone(score)}`}
      >
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <div className="text-xs font-bold uppercase tracking-wider flex items-center gap-2">
              <Search className="w-4 h-4" /> Reverse Image Search
            </div>
            <div className="text-sm">
              {data.found
                ? `Found ${data.matchCount} matching source${data.matchCount === 1 ? "" : "s"}`
                : "Image appears original — no matches"}
            </div>
          </div>
          <div className="text-3xl font-bold font-mono">{score}</div>
        </div>

        {data.riskIndicators && data.riskIndicators.length > 0 && (
          <ul className="mt-3 space-y-1.5 text-xs">
            {data.riskIndicators.map((ri, i) => (
              <li key={i} className="flex items-start gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" />
                <span>{ri}</span>
              </li>
            ))}
          </ul>
        )}
      </motion.div>

      {/* Matches */}
      {data.sources && data.sources.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
            Matching sources
          </h3>
          {data.sources.map((s, i) => (
            <div key={i} className="border border-border rounded-lg p-3 bg-background/40">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <div className="font-semibold text-sm truncate">{s.title}</div>
                  {s.url && (
                    <a
                      href={s.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-xs text-primary hover:underline break-all"
                    >
                      {s.url} <ExternalLink className="w-3 h-3 shrink-0" />
                    </a>
                  )}
                </div>
                <span
                  className={`text-[10px] font-bold px-2 py-1 rounded-md uppercase tracking-wider ${
                    s.isSuspicious ? "bg-red-500/20 text-red-300" : "bg-muted text-muted-foreground"
                  }`}
                >
                  {s.category}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap gap-3 text-[11px] text-muted-foreground font-mono">
                {typeof s.confidence === "number" && <span>match {(s.confidence * 100).toFixed(0)}%</span>}
                {typeof s.distance === "number" && <span>hamming {s.distance}</span>}
                {typeof s.reports === "number" && <span>reports {s.reports}</span>}
                {s.first_seen && <span>seen {s.first_seen}</span>}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Always offer Google Lens as a manual escalation */}
      {data.previewUrl && (
        <a
          href={`https://lens.google.com/uploadbyurl?url=${encodeURIComponent(data.previewUrl)}`}
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center gap-1.5 text-sm text-primary hover:underline"
        >
          <ExternalLink className="w-3.5 h-3.5" />
          Also try Google Lens reverse image search
        </a>
      )}
    </div>
  );
};

export default ReverseImageSearchPanel;
