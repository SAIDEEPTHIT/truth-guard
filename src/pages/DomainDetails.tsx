import { useState, useEffect } from "react";
import { useParams, Link } from "react-router-dom";
import { motion } from "framer-motion";
import { ArrowLeft, ThumbsUp, ThumbsDown, ExternalLink, AlertTriangle, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { toast } from "@/hooks/use-toast";
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import {
  fetchDomainDetails,
  upvoteDomain,
  downvoteDomain,
  type DomainDetails as DomainDetailsType,
} from "@/lib/blocklistApi";

const COLORS = ["#ef4444", "#f97316", "#eab308", "#8b5cf6", "#6b7280"];

const DomainDetails = () => {
  const { domain } = useParams<{ domain: string }>();
  const [details, setDetails] = useState<DomainDetailsType | null>(null);
  const [loading, setLoading] = useState(true);

  const load = async () => {
    if (!domain) return;
    setLoading(true);
    try {
      const data = await fetchDomainDetails(decodeURIComponent(domain));
      setDetails(data);
    } catch {
      toast({ title: "Error", description: "Domain not found or backend unreachable", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [domain]);

  const handleVote = async (type: "up" | "down") => {
    if (!domain) return;
    try {
      if (type === "up") await upvoteDomain(decodeURIComponent(domain));
      else await downvoteDomain(decodeURIComponent(domain));
      load();
    } catch {
      toast({ title: "Error", description: "Vote failed", variant: "destructive" });
    }
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <p className="text-muted-foreground">Loading domain details...</p>
      </div>
    );
  }

  if (!details) {
    return (
      <div className="min-h-screen bg-background flex flex-col items-center justify-center gap-4">
        <AlertTriangle className="w-12 h-12 text-muted-foreground" />
        <p className="text-lg text-muted-foreground">Domain not found</p>
        <Button asChild>
          <Link to="/blocklist">← Back to Blocklist</Link>
        </Button>
      </div>
    );
  }

  const totalVotes = details.upvotes + details.downvotes;
  const upPercent = totalVotes > 0 ? (details.upvotes / totalVotes) * 100 : 50;

  // Threat type breakdown from reports
  const threatCounts: Record<string, number> = {};
  details.reports.forEach((r) => {
    threatCounts[r.threat_type] = (threatCounts[r.threat_type] || 0) + 1;
  });
  const pieData = Object.entries(threatCounts).map(([name, value]) => ({ name, value }));

  return (
    <div className="min-h-screen bg-background p-4 sm:p-8">
      <div className="max-w-4xl mx-auto space-y-6">
        <Button variant="ghost" asChild>
          <Link to="/blocklist">
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to Blocklist
          </Link>
        </Button>

        <motion.div initial={{ opacity: 0, y: -10 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="border-destructive/30">
            <CardHeader>
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
                <div>
                  <CardTitle className="text-2xl font-mono break-all flex items-center gap-2">
                    <AlertTriangle className="w-6 h-6 text-destructive flex-shrink-0" />
                    {details.domain}
                  </CardTitle>
                  <p className="text-sm text-muted-foreground mt-1">
                    Reported {details.report_count} time{details.report_count !== 1 ? "s" : ""} •
                    First reported {new Date(details.created_at).toLocaleDateString()}
                  </p>
                </div>
                <Badge variant="destructive" className="text-base px-4 py-1">
                  {details.threat_type}
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="space-y-6">
              {/* Vote Bar */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-green-600 font-medium">👍 {details.upvotes} Upvotes</span>
                  <span className="text-red-500 font-medium">👎 {details.downvotes} Downvotes</span>
                </div>
                <Progress value={upPercent} className="h-3" />
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" className="text-green-600" onClick={() => handleVote("up")}>
                    <ThumbsUp className="w-4 h-4 mr-1" /> Upvote
                  </Button>
                  <Button variant="outline" size="sm" className="text-red-500" onClick={() => handleVote("down")}>
                    <ThumbsDown className="w-4 h-4 mr-1" /> Downvote
                  </Button>
                </div>
              </div>

              {/* Pie Chart */}
              {pieData.length > 0 && (
                <div>
                  <h3 className="font-semibold mb-2">Threat Type Breakdown</h3>
                  <div className="h-48">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={pieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={40}
                          outerRadius={70}
                          paddingAngle={5}
                          dataKey="value"
                          label={({ name, value }) => `${name} (${value})`}
                        >
                          {pieData.map((_, i) => (
                            <Cell key={i} fill={COLORS[i % COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>

        {/* Reports */}
        <div className="space-y-3">
          <h2 className="text-xl font-semibold">Reports ({details.reports.length})</h2>
          {details.reports.map((r, i) => (
            <motion.div
              key={r.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Card>
                <CardContent className="p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <Badge variant="outline">{r.threat_type}</Badge>
                    <span className="text-xs text-muted-foreground flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {new Date(r.created_at).toLocaleString()}
                    </span>
                  </div>
                  {r.description && (
                    <p className="text-sm text-foreground">{r.description}</p>
                  )}
                  {r.proof_link && (
                    <a
                      href={r.proof_link}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-sm text-primary hover:underline flex items-center gap-1"
                    >
                      <ExternalLink className="w-3 h-3" />
                      Proof Link
                    </a>
                  )}
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span>👍 {r.upvotes}</span>
                    <span>👎 {r.downvotes}</span>
                    <span>by {r.user_id}</span>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default DomainDetails;
