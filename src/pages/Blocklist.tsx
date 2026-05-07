import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Flag, Search, TrendingUp, ThumbsUp, ThumbsDown, ExternalLink, BarChart3 } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "@/hooks/use-toast";
import BlocklistModal from "@/components/truthshield/BlocklistModal";
import {
  fetchBlocklist,
  upvoteDomain,
  downvoteDomain,
  seedDemoData,
  THREAT_TYPES,
  type BlockedDomain,
} from "@/lib/blocklistApi";

const THREAT_COLORS: Record<string, string> = {
  Phishing: "bg-red-500/10 text-red-500 border-red-500/30",
  "Job Scam": "bg-orange-500/10 text-orange-500 border-orange-500/30",
  Lottery: "bg-yellow-500/10 text-yellow-500 border-yellow-500/30",
  "Financial Fraud": "bg-purple-500/10 text-purple-500 border-purple-500/30",
  Other: "bg-muted text-muted-foreground border-border",
};

const Blocklist = () => {
  const [domains, setDomains] = useState<BlockedDomain[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [threatFilter, setThreatFilter] = useState<string>("all");
  const [sort, setSort] = useState("recently_added");
  const [page, setPage] = useState(0);
  const LIMIT = 12;

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetchBlocklist({
        limit: LIMIT,
        offset: page * LIMIT,
        threat_type: threatFilter !== "all" ? threatFilter : undefined,
        sort,
        search: search || undefined,
      });
      setDomains(res.domains);
      setTotal(res.total);
    } catch {
      toast({ title: "Error", description: "Failed to load blocklist. Is the backend running?", variant: "destructive" });
    } finally {
      setLoading(false);
    }
  }, [page, threatFilter, sort, search]);

  useEffect(() => { load(); }, [load]);

  const handleVote = async (domain: string, type: "up" | "down") => {
    try {
      if (type === "up") await upvoteDomain(domain);
      else await downvoteDomain(domain);
      load();
    } catch {
      toast({ title: "Error", description: "Vote failed", variant: "destructive" });
    }
  };

  const handleSeed = async () => {
    try {
      await seedDemoData();
      toast({ title: "✅ Demo Data Seeded", description: "Sample domains added for demo." });
      load();
    } catch {
      toast({ title: "Error", description: "Seeding failed", variant: "destructive" });
    }
  };

  return (
    <div className="min-h-screen bg-background p-4 sm:p-8">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -20 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4"
        >
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Flag className="w-8 h-8 text-destructive" />
              Community Blocklist
            </h1>
            <p className="text-muted-foreground mt-1">
              {total} domains reported by the community
            </p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" asChild>
              <Link to="/blocklist-stats">
                <BarChart3 className="w-4 h-4 mr-1" />
                Stats
              </Link>
            </Button>
            <Button variant="secondary" size="sm" onClick={handleSeed}>
              Seed Demo Data
            </Button>
            <BlocklistModal onSuccess={load} />
          </div>
        </motion.div>

        {/* Filters */}
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search domains..."
              className="pl-10"
              value={search}
              onChange={(e) => { setSearch(e.target.value); setPage(0); }}
            />
          </div>
          <Select value={threatFilter} onValueChange={(v) => { setThreatFilter(v); setPage(0); }}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Filter by type" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Types</SelectItem>
              {THREAT_TYPES.map((t) => (
                <SelectItem key={t} value={t}>{t}</SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Select value={sort} onValueChange={(v) => { setSort(v); setPage(0); }}>
            <SelectTrigger className="w-[180px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="recently_added">Recently Added</SelectItem>
              <SelectItem value="most_reported">Most Reported</SelectItem>
              <SelectItem value="highest_rated">Highest Rated</SelectItem>
            </SelectContent>
          </Select>
        </div>

        {/* Domain Cards */}
        {loading ? (
          <div className="text-center py-16 text-muted-foreground">Loading...</div>
        ) : domains.length === 0 ? (
          <div className="text-center py-16">
            <Flag className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg text-muted-foreground">No domains found</p>
            <p className="text-sm text-muted-foreground mt-1">
              Click "Seed Demo Data" to add sample data or report a domain.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {domains.map((d, i) => (
              <motion.div
                key={d.id}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <Card className="hover:border-primary/30 transition-colors h-full">
                  <CardContent className="p-5 space-y-3">
                    <div className="flex items-start justify-between">
                      <h3 className="font-mono font-semibold text-sm break-all">{d.domain}</h3>
                      <Badge variant="outline" className={THREAT_COLORS[d.threat_type] || THREAT_COLORS.Other}>
                        {d.threat_type}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-4 text-sm text-muted-foreground">
                      <span className="flex items-center gap-1">
                        <TrendingUp className="w-3.5 h-3.5" />
                        {d.report_count} report{d.report_count !== 1 ? "s" : ""}
                      </span>
                      <span>{new Date(d.created_at).toLocaleDateString()}</span>
                    </div>
                    <div className="flex items-center justify-between pt-2">
                      <div className="flex items-center gap-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 gap-1 text-green-600 hover:text-green-700 hover:bg-green-50"
                          onClick={() => handleVote(d.domain, "up")}
                        >
                          <ThumbsUp className="w-3.5 h-3.5" />
                          {d.upvotes}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="h-8 gap-1 text-red-500 hover:text-red-600 hover:bg-red-50"
                          onClick={() => handleVote(d.domain, "down")}
                        >
                          <ThumbsDown className="w-3.5 h-3.5" />
                          {d.downvotes}
                        </Button>
                      </div>
                      <Button variant="outline" size="sm" asChild>
                        <Link to={`/blocklist/${encodeURIComponent(d.domain)}`}>
                          <ExternalLink className="w-3.5 h-3.5 mr-1" />
                          Details
                        </Link>
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            ))}
          </div>
        )}

        {/* Pagination */}
        {total > LIMIT && (
          <div className="flex justify-center gap-2 pt-4">
            <Button
              variant="outline"
              size="sm"
              disabled={page === 0}
              onClick={() => setPage(page - 1)}
            >
              Previous
            </Button>
            <span className="flex items-center text-sm text-muted-foreground px-3">
              Page {page + 1} of {Math.ceil(total / LIMIT)}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={(page + 1) * LIMIT >= total}
              onClick={() => setPage(page + 1)}
            >
              Next
            </Button>
          </div>
        )}
      </div>
    </div>
  );
};

export default Blocklist;
