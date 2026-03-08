import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Trash2, Clock, ChevronRight, Search } from "lucide-react";
import RiskGauge from "./RiskGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface HistoryItem {
  id: string;
  timestamp: number;
  type: "text" | "image";
  preview: string;
  risk_score: number;
  classification: string;
}

export function addToHistory(type: "text" | "image", preview: string, risk_score: number, classification: string) {
  const history: HistoryItem[] = JSON.parse(localStorage.getItem("truthshield_history") || "[]");
  history.unshift({
    id: crypto.randomUUID(),
    timestamp: Date.now(),
    type,
    preview: preview.slice(0, 200),
    risk_score,
    classification,
  });
  localStorage.setItem("truthshield_history", JSON.stringify(history.slice(0, 50)));
}

const AnalysisHistory = () => {
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [search, setSearch] = useState("");

  useEffect(() => {
    setHistory(JSON.parse(localStorage.getItem("truthshield_history") || "[]"));
  }, []);

  const filtered = history.filter(item =>
    item.preview.toLowerCase().includes(search.toLowerCase())
  );

  const clearHistory = () => {
    localStorage.removeItem("truthshield_history");
    setHistory([]);
  };

  return (
    <div className="min-h-screen">
      <div className="max-w-4xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold">Analysis History</h1>
            <p className="text-muted-foreground text-sm mt-1">{history.length} analyses stored locally</p>
          </div>
          {history.length > 0 && (
            <Button variant="outline" size="sm" onClick={clearHistory} className="gap-2">
              <Trash2 className="w-4 h-4" /> Clear All
            </Button>
          )}
        </div>

        {history.length > 0 && (
          <div className="relative mb-6">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search history..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="pl-10"
            />
          </div>
        )}

        {filtered.length === 0 ? (
          <div className="text-center py-20 text-muted-foreground">
            <Clock className="w-12 h-12 mx-auto mb-4 opacity-30" />
            <p className="text-lg font-medium">{history.length === 0 ? "No analyses yet" : "No matching results"}</p>
            <p className="text-sm mt-1">Your analysis results will appear here.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <AnimatePresence>
              {filtered.map((item, i) => (
                <motion.div
                  key={item.id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ delay: i * 0.03 }}
                  className="flex items-center gap-4 p-4 rounded-lg border border-border bg-card hover:bg-secondary/30 transition-colors"
                >
                  <RiskGauge score={item.risk_score} classification={item.classification} size="sm" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-secondary text-muted-foreground uppercase">
                        {item.type}
                      </span>
                      <span className={`text-xs font-semibold ${
                        item.classification === "Safe" || item.classification === "Likely Authentic"
                          ? "text-success"
                          : item.classification === "Suspicious" || item.classification === "Possibly AI-Generated"
                          ? "text-warning"
                          : "text-destructive"
                      }`}>
                        {item.classification}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground truncate">{item.preview}</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      {new Date(item.timestamp).toLocaleString()}
                    </p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                </motion.div>
              ))}
            </AnimatePresence>
          </div>
        )}
      </div>
    </div>
  );
};

export default AnalysisHistory;
