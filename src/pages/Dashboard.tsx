import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, BarChart3, Target, Activity, AlertTriangle, CheckCircle2,
  TrendingUp, Trash2, Tag
} from "lucide-react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  computeMetrics, getAllRecords, labelRecord, clearAllRecords,
  type EvalMetrics, type AnalysisRecord
} from "@/lib/analysisStore";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, Legend,
} from "recharts";

const COLORS = {
  safe: "hsl(142 71% 45%)",
  suspicious: "hsl(45 93% 47%)",
  high_risk: "hsl(0 72% 51%)",
  primary: "hsl(187 80% 48%)",
  accent: "hsl(217 91% 60%)",
};

const DashboardPage = () => {
  const { seniorMode } = useSeniorMode();
  const [metrics, setMetrics] = useState<EvalMetrics | null>(null);
  const [records, setRecords] = useState<AnalysisRecord[]>([]);

  const refresh = () => {
    setMetrics(computeMetrics());
    setRecords(getAllRecords().reverse());
  };

  useEffect(() => { refresh(); }, []);

  const handleLabel = (id: string, label: "safe" | "suspicious" | "high_risk") => {
    labelRecord(id, label);
    refresh();
  };

  const handleClear = () => {
    if (confirm("Clear all analysis records? This cannot be undone.")) {
      clearAllRecords();
      refresh();
    }
  };

  if (!metrics) return null;

  const pieData = [
    { name: "Safe", value: metrics.riskDistribution.safe, fill: COLORS.safe },
    { name: "Suspicious", value: metrics.riskDistribution.suspicious, fill: COLORS.suspicious },
    { name: "High Risk", value: metrics.riskDistribution.high_risk, fill: COLORS.high_risk },
  ].filter(d => d.value > 0);

  const confusionClasses = ["safe", "suspicious", "high_risk"];
  const classLabels: Record<string, string> = { safe: "Safe", suspicious: "Suspicious", high_risk: "High Risk" };

  return (
    <div className="min-h-screen">
      <div className="max-w-7xl mx-auto px-4 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className={`font-bold mb-1 ${seniorMode ? "text-3xl" : "text-2xl"}`}>
              <BarChart3 className="w-6 h-6 inline-block mr-2 text-primary" />
              Evaluation Dashboard
            </h1>
            <p className={`text-muted-foreground ${seniorMode ? "text-lg" : "text-sm"}`}>
              Model performance metrics, analysis statistics, and classification accuracy.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={handleClear} className="gap-1.5 text-destructive">
            <Trash2 className="w-3.5 h-3.5" /> Clear Data
          </Button>
        </div>

        {/* KPI Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          {[
            {
              icon: Activity, label: "Total Analyses", value: metrics.total,
              sub: `${metrics.riskDistribution.high_risk} high-risk`, color: "text-primary"
            },
            {
              icon: Target, label: "Accuracy", value: metrics.labeled > 0 ? `${(metrics.accuracy * 100).toFixed(1)}%` : "N/A",
              sub: `${metrics.labeled} labeled`, color: "text-success"
            },
            {
              icon: TrendingUp, label: "Avg Risk Score", value: metrics.avgRiskScore,
              sub: "out of 100", color: metrics.avgRiskScore > 60 ? "text-destructive" : metrics.avgRiskScore > 30 ? "text-warning" : "text-success"
            },
            {
              icon: AlertTriangle, label: "High Risk Rate",
              value: metrics.total > 0 ? `${((metrics.riskDistribution.high_risk / metrics.total) * 100).toFixed(1)}%` : "0%",
              sub: "of all analyses", color: "text-destructive"
            },
          ].map((kpi, i) => (
            <motion.div key={i} initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.1 }}>
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 mb-2">
                    <kpi.icon className={`w-4 h-4 ${kpi.color}`} />
                    <span className="text-xs font-medium text-muted-foreground">{kpi.label}</span>
                  </div>
                  <div className={`text-2xl font-bold font-mono ${kpi.color}`}>{kpi.value}</div>
                  <p className="text-xs text-muted-foreground mt-1">{kpi.sub}</p>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>

        <Tabs defaultValue="overview" className="space-y-6">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="evaluation">Model Evaluation</TabsTrigger>
            <TabsTrigger value="records">Analysis Records</TabsTrigger>
          </TabsList>

          {/* Overview Tab */}
          <TabsContent value="overview">
            <div className="grid lg:grid-cols-2 gap-6">
              {/* Time Series */}
              <Card>
                <CardHeader><CardTitle className="text-sm">Analyses Over Time (30 Days)</CardTitle></CardHeader>
                <CardContent>
                  {metrics.total > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <LineChart data={metrics.timeSeriesDaily}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                        <XAxis dataKey="date" tick={{ fontSize: 10 }} tickFormatter={d => d.slice(5)} stroke="hsl(var(--muted-foreground))" />
                        <YAxis tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                        <Legend />
                        <Line type="monotone" dataKey="count" stroke={COLORS.primary} name="Total" strokeWidth={2} dot={false} />
                        <Line type="monotone" dataKey="highRisk" stroke={COLORS.high_risk} name="High Risk" strokeWidth={2} dot={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-muted-foreground text-sm">
                      No analyses yet. Go analyze some text to populate data.
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Distribution Pie */}
              <Card>
                <CardHeader><CardTitle className="text-sm">Risk Distribution</CardTitle></CardHeader>
                <CardContent>
                  {pieData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <PieChart>
                        <Pie data={pieData} cx="50%" cy="50%" innerRadius={60} outerRadius={90} paddingAngle={3} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                          {pieData.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex items-center justify-center text-muted-foreground text-sm">
                      No data yet
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Evaluation Tab */}
          <TabsContent value="evaluation">
            <div className="grid lg:grid-cols-2 gap-6">
              {/* Per-class Metrics */}
              <Card>
                <CardHeader><CardTitle className="text-sm">Per-Class Precision / Recall / F1</CardTitle></CardHeader>
                <CardContent>
                  {metrics.labeled > 0 ? (
                    <ResponsiveContainer width="100%" height={250}>
                      <BarChart data={confusionClasses.map(c => ({
                        name: classLabels[c],
                        Precision: +(metrics.precision[c] * 100).toFixed(1),
                        Recall: +(metrics.recall[c] * 100).toFixed(1),
                        F1: +(metrics.f1[c] * 100).toFixed(1),
                      }))}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                        <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="hsl(var(--muted-foreground))" />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 10 }} stroke="hsl(var(--muted-foreground))" />
                        <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                        <Legend />
                        <Bar dataKey="Precision" fill={COLORS.primary} radius={[4, 4, 0, 0]} />
                        <Bar dataKey="Recall" fill={COLORS.accent} radius={[4, 4, 0, 0]} />
                        <Bar dataKey="F1" fill={COLORS.safe} radius={[4, 4, 0, 0]} />
                      </BarChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="h-[250px] flex flex-col items-center justify-center text-muted-foreground text-sm gap-2">
                      <Tag className="w-8 h-8 opacity-30" />
                      <p>Label some records in the "Analysis Records" tab to see evaluation metrics.</p>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Confusion Matrix */}
              <Card>
                <CardHeader><CardTitle className="text-sm">Confusion Matrix</CardTitle></CardHeader>
                <CardContent>
                  {metrics.labeled > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr>
                            <th className="p-2 text-xs text-muted-foreground border-b border-border">Actual ↓ / Predicted →</th>
                            {confusionClasses.map(c => (
                              <th key={c} className="p-2 text-xs font-semibold border-b border-border">{classLabels[c]}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {confusionClasses.map(actual => (
                            <tr key={actual}>
                              <td className="p-2 text-xs font-semibold border-b border-border">{classLabels[actual]}</td>
                              {confusionClasses.map(pred => {
                                const val = metrics.confusionMatrix[actual][pred];
                                const isDiag = actual === pred;
                                return (
                                  <td key={pred} className={`p-2 text-center font-mono text-sm border-b border-border ${isDiag ? "bg-primary/10 font-bold" : ""}`}>
                                    {val}
                                  </td>
                                );
                              })}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <p className="text-xs text-muted-foreground mt-3">
                        Diagonal values (highlighted) = correct predictions. Overall Accuracy: <strong>{(metrics.accuracy * 100).toFixed(1)}%</strong> ({metrics.labeled} labeled samples)
                      </p>
                    </div>
                  ) : (
                    <div className="h-[250px] flex flex-col items-center justify-center text-muted-foreground text-sm gap-2">
                      <Tag className="w-8 h-8 opacity-30" />
                      <p>No labeled data yet</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          {/* Records Tab */}
          <TabsContent value="records">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center justify-between">
                  <span>Recent Analyses ({records.length})</span>
                  <span className="text-xs text-muted-foreground font-normal">
                    Click a label button to mark the true classification for evaluation
                  </span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                {records.length > 0 ? (
                  <div className="space-y-2 max-h-[500px] overflow-y-auto">
                    {records.slice(0, 50).map(rec => (
                      <div key={rec.id} className={`flex items-center gap-3 p-3 rounded-lg border border-border bg-secondary/20 ${rec.true_label ? "opacity-80" : ""}`}>
                        <div className={`w-2 h-2 rounded-full shrink-0 ${
                          rec.classification === "Safe" ? "bg-success" : rec.classification === "Suspicious" ? "bg-warning" : "bg-destructive"
                        }`} />
                        <div className="flex-1 min-w-0">
                          <p className="text-xs truncate">{rec.input_preview}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <span className="text-xs text-muted-foreground">{rec.type}</span>
                            <span className="text-xs font-mono font-semibold">{rec.risk_score}/100</span>
                            <span className={`text-xs font-semibold ${
                              rec.classification === "Safe" ? "text-success" : rec.classification === "Suspicious" ? "text-warning" : "text-destructive"
                            }`}>{rec.classification}</span>
                            {rec.true_label && (
                              <span className="text-xs px-1.5 py-0.5 rounded bg-primary/10 text-primary">✓ {classLabels[rec.true_label]}</span>
                            )}
                          </div>
                        </div>
                        {!rec.true_label && (
                          <div className="flex gap-1 shrink-0">
                            <button onClick={() => handleLabel(rec.id, "safe")} className="text-[10px] px-2 py-1 rounded border border-success/30 text-success hover:bg-success/10" title="Mark as actually Safe">
                              <CheckCircle2 className="w-3 h-3" />
                            </button>
                            <button onClick={() => handleLabel(rec.id, "suspicious")} className="text-[10px] px-2 py-1 rounded border border-warning/30 text-warning hover:bg-warning/10" title="Mark as actually Suspicious">
                              <AlertTriangle className="w-3 h-3" />
                            </button>
                            <button onClick={() => handleLabel(rec.id, "high_risk")} className="text-[10px] px-2 py-1 rounded border border-destructive/30 text-destructive hover:bg-destructive/10" title="Mark as actually High Risk">
                              <Shield className="w-3 h-3" />
                            </button>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="py-12 text-center text-muted-foreground text-sm">
                    No analysis records yet. Analyze some text or images to populate data.
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default DashboardPage;
