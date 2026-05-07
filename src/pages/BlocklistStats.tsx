import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, Flag, FileText, TrendingUp, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  LineChart, Line,
} from "recharts";
import { toast } from "@/hooks/use-toast";
import { fetchBlocklistStats, type BlocklistStats as StatsType } from "@/lib/blocklistApi";

const COLORS = ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#6b7280", "#3b82f6"];

const BlocklistStats = () => {
  const [stats, setStats] = useState<StatsType | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchBlocklistStats()
      .then(setStats)
      .catch(() => toast({ title: "Error", description: "Failed to load stats", variant: "destructive" }))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Loading statistics...</p>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4">
        <p className="text-muted-foreground">Unable to load statistics. Is the backend running?</p>
        <Button asChild>
          <Link to="/blocklist">← Back to Blocklist</Link>
        </Button>
      </div>
    );
  }

  const pieData = Object.entries(stats.threat_types).map(([name, value]) => ({ name, value }));
  const barData = stats.top_10.map((d) => ({
    domain: d.domain.length > 20 ? d.domain.slice(0, 18) + "…" : d.domain,
    reports: d.report_count,
  }));

  return (
    <div className="min-h-screen bg-background p-4 sm:p-8">
      <div className="max-w-6xl mx-auto space-y-6">
        <Button variant="ghost" asChild>
          <Link to="/blocklist">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Blocklist
          </Link>
        </Button>

        <motion.h1
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-3xl font-bold flex items-center gap-3"
        >
          <ShieldAlert className="w-8 h-8 text-destructive" />
          Blocklist Analytics
        </motion.h1>

        {/* Stat Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: "Total Domains", value: stats.total_domains, icon: Flag, color: "text-destructive" },
            { label: "Total Reports", value: stats.total_reports, icon: FileText, color: "text-primary" },
            { label: "Threat Types", value: Object.keys(stats.threat_types).length, icon: ShieldAlert, color: "text-orange-500" },
            { label: "Top Reports", value: stats.top_10[0]?.report_count || 0, icon: TrendingUp, color: "text-green-500" },
          ].map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: i * 0.1 }}
            >
              <Card>
                <CardContent className="p-6 flex items-center gap-4">
                  <s.icon className={`w-10 h-10 ${s.color}`} />
                  <div>
                    <p className="text-3xl font-bold">{s.value}</p>
                    <p className="text-sm text-muted-foreground">{s.label}</p>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Threat Type Pie */}
          <Card>
            <CardHeader>
              <CardTitle>Threat Type Distribution</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      outerRadius={90}
                      paddingAngle={3}
                      dataKey="value"
                      label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    >
                      {pieData.map((_, i) => (
                        <Cell key={i} fill={COLORS[i % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>

          {/* Top 10 Bar */}
          <Card>
            <CardHeader>
              <CardTitle>Top 10 Most Reported Domains</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={barData} layout="vertical">
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis type="number" />
                    <YAxis dataKey="domain" type="category" width={130} tick={{ fontSize: 11 }} />
                    <Tooltip />
                    <Bar dataKey="reports" fill="#ef4444" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Timeline */}
        {stats.timeline.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle>Reports Over Time (Last 30 Days)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="h-64">
                <ResponsiveContainer width="100%" height="100%">
                  <LineChart data={stats.timeline}>
                    <CartesianGrid strokeDasharray="3 3" />
                    <XAxis dataKey="date" tick={{ fontSize: 11 }} />
                    <YAxis />
                    <Tooltip />
                    <Line type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} dot={{ r: 4 }} />
                  </LineChart>
                </ResponsiveContainer>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
};

export default BlocklistStats;
