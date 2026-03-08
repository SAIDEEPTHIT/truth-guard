// TruthShield Analysis Store — localStorage-based analytics tracking

export interface AnalysisRecord {
  id: string;
  timestamp: number;
  type: "text" | "image";
  input_preview: string;
  risk_score: number;
  classification: string;
  signals: {
    ai_generated: number;
    scam_keywords: number;
    emotional_manipulation: number;
  };
  true_label?: "safe" | "suspicious" | "high_risk"; // for evaluation
}

const STORE_KEY = "truthshield_analytics";

function getRecords(): AnalysisRecord[] {
  try {
    return JSON.parse(localStorage.getItem(STORE_KEY) || "[]");
  } catch {
    return [];
  }
}

function saveRecords(records: AnalysisRecord[]) {
  localStorage.setItem(STORE_KEY, JSON.stringify(records));
}

export function recordAnalysis(record: Omit<AnalysisRecord, "id" | "timestamp">) {
  const records = getRecords();
  records.push({
    ...record,
    id: crypto.randomUUID(),
    timestamp: Date.now(),
  });
  // Keep last 500
  if (records.length > 500) records.splice(0, records.length - 500);
  saveRecords(records);
}

export function getAllRecords(): AnalysisRecord[] {
  return getRecords();
}

export function labelRecord(id: string, label: "safe" | "suspicious" | "high_risk") {
  const records = getRecords();
  const rec = records.find(r => r.id === id);
  if (rec) {
    rec.true_label = label;
    saveRecords(records);
  }
}

export function clearAllRecords() {
  localStorage.removeItem(STORE_KEY);
}

// Evaluation metrics
export interface EvalMetrics {
  total: number;
  labeled: number;
  accuracy: number;
  precision: Record<string, number>;
  recall: Record<string, number>;
  f1: Record<string, number>;
  confusionMatrix: Record<string, Record<string, number>>;
  riskDistribution: { safe: number; suspicious: number; high_risk: number };
  timeSeriesDaily: { date: string; count: number; highRisk: number }[];
  avgRiskScore: number;
}

export function computeMetrics(): EvalMetrics {
  const records = getRecords();
  const total = records.length;

  const riskDistribution = { safe: 0, suspicious: 0, high_risk: 0 };
  records.forEach(r => {
    if (r.classification === "Safe") riskDistribution.safe++;
    else if (r.classification === "Suspicious") riskDistribution.suspicious++;
    else riskDistribution.high_risk++;
  });

  const avgRiskScore = total > 0 ? Math.round(records.reduce((s, r) => s + r.risk_score, 0) / total) : 0;

  // Time series (last 30 days)
  const now = Date.now();
  const dailyMap: Record<string, { count: number; highRisk: number }> = {};
  for (let i = 29; i >= 0; i--) {
    const d = new Date(now - i * 86400000);
    const key = d.toISOString().slice(0, 10);
    dailyMap[key] = { count: 0, highRisk: 0 };
  }
  records.forEach(r => {
    const key = new Date(r.timestamp).toISOString().slice(0, 10);
    if (dailyMap[key]) {
      dailyMap[key].count++;
      if (r.classification === "High Risk") dailyMap[key].highRisk++;
    }
  });
  const timeSeriesDaily = Object.entries(dailyMap).map(([date, v]) => ({ date, ...v }));

  // Evaluation metrics from labeled records
  const labeled = records.filter(r => r.true_label);
  const classes = ["safe", "suspicious", "high_risk"];

  const confusionMatrix: Record<string, Record<string, number>> = {};
  classes.forEach(a => {
    confusionMatrix[a] = {};
    classes.forEach(b => { confusionMatrix[a][b] = 0; });
  });

  const predToKey = (c: string) => c === "Safe" ? "safe" : c === "Suspicious" ? "suspicious" : "high_risk";

  labeled.forEach(r => {
    const pred = predToKey(r.classification);
    const actual = r.true_label!;
    if (confusionMatrix[actual] && confusionMatrix[actual][pred] !== undefined) {
      confusionMatrix[actual][pred]++;
    }
  });

  let correct = 0;
  classes.forEach(c => { correct += confusionMatrix[c][c]; });
  const accuracy = labeled.length > 0 ? correct / labeled.length : 0;

  const precision: Record<string, number> = {};
  const recall: Record<string, number> = {};
  const f1: Record<string, number> = {};

  classes.forEach(c => {
    let tp = confusionMatrix[c][c];
    let fpSum = 0, fnSum = 0;
    classes.forEach(other => {
      if (other !== c) {
        fpSum += confusionMatrix[other][c]; // predicted c but was other
        fnSum += confusionMatrix[c][other]; // was c but predicted other
      }
    });
    precision[c] = (tp + fpSum) > 0 ? tp / (tp + fpSum) : 0;
    recall[c] = (tp + fnSum) > 0 ? tp / (tp + fnSum) : 0;
    f1[c] = (precision[c] + recall[c]) > 0
      ? 2 * precision[c] * recall[c] / (precision[c] + recall[c])
      : 0;
  });

  return {
    total,
    labeled: labeled.length,
    accuracy,
    precision,
    recall,
    f1,
    confusionMatrix,
    riskDistribution,
    timeSeriesDaily,
    avgRiskScore,
  };
}
