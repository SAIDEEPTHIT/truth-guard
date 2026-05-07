import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { AlertTriangle, X, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";

interface DomainWarningBannerProps {
  domain: string;
  threatType: string;
  reportCount: number;
  upvotes: number;
  downvotes: number;
  onProceed?: () => void;
}

const DomainWarningBanner = ({
  domain,
  threatType,
  reportCount,
  upvotes,
  downvotes,
  onProceed,
}: DomainWarningBannerProps) => {
  const [dismissed, setDismissed] = useState(false);

  if (dismissed) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ y: -100, opacity: 0 }}
        animate={{ y: 0, opacity: 1 }}
        exit={{ y: -100, opacity: 0 }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="bg-destructive/10 border border-destructive/30 rounded-lg p-4 mb-4"
      >
        <div className="flex items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-6 h-6 text-destructive flex-shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="font-semibold text-destructive">
                ⚠️ This domain has been reported by {reportCount} user{reportCount !== 1 ? "s" : ""} as{" "}
                <span className="underline">{threatType}</span>
              </p>
              <p className="text-sm text-muted-foreground">
                Community rating: 👍 {upvotes} | 👎 {downvotes}
              </p>
              <div className="flex gap-2 mt-2">
                <Button variant="outline" size="sm" asChild>
                  <Link to={`/blocklist/${encodeURIComponent(domain)}`}>
                    <ExternalLink className="w-3 h-3 mr-1" />
                    View Details
                  </Link>
                </Button>
                {onProceed && (
                  <Button variant="ghost" size="sm" onClick={onProceed}>
                    Proceed Anyway
                  </Button>
                )}
              </div>
            </div>
          </div>
          <button
            onClick={() => setDismissed(true)}
            className="text-muted-foreground hover:text-foreground"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </motion.div>
    </AnimatePresence>
  );
};

export default DomainWarningBanner;
