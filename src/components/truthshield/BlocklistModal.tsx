import { useState } from "react";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Flag } from "lucide-react";
import { toast } from "@/hooks/use-toast";
import { reportDomain, THREAT_TYPES } from "@/lib/blocklistApi";

interface BlocklistModalProps {
  onSuccess?: () => void;
  trigger?: React.ReactNode;
}

const BlocklistModal = ({ onSuccess, trigger }: BlocklistModalProps) => {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [domain, setDomain] = useState("");
  const [threatType, setThreatType] = useState<string>("Phishing");
  const [description, setDescription] = useState("");
  const [proofLink, setProofLink] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim()) {
      toast({ title: "Error", description: "Please enter a domain", variant: "destructive" });
      return;
    }

    setLoading(true);
    try {
      const result = await reportDomain({
        domain: domain.trim(),
        threat_type: threatType,
        description: description.trim(),
        proof_link: proofLink.trim(),
      });
      toast({ title: "✅ Domain Reported", description: result.message });
      setDomain("");
      setDescription("");
      setProofLink("");
      setOpen(false);
      onSuccess?.();
    } catch (err: any) {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        {trigger || (
          <Button variant="destructive" size="sm" className="gap-2">
            <Flag className="w-4 h-4" />
            Report Domain
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Flag className="w-5 h-5 text-destructive" />
            Report Malicious Domain
          </DialogTitle>
        </DialogHeader>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="domain">Domain *</Label>
            <Input
              id="domain"
              placeholder="e.g. fake-bank-login.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
            <p className="text-xs text-muted-foreground">
              http:// and www. will be stripped automatically
            </p>
          </div>
          <div className="space-y-2">
            <Label>Threat Type</Label>
            <Select value={threatType} onValueChange={setThreatType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {THREAT_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>{t}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="description">Description (optional)</Label>
            <Textarea
              id="description"
              placeholder="Describe why this domain is malicious..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              maxLength={500}
              rows={3}
            />
            <p className="text-xs text-muted-foreground">{description.length}/500</p>
          </div>
          <div className="space-y-2">
            <Label htmlFor="proof">Proof Link (optional)</Label>
            <Input
              id="proof"
              placeholder="https://..."
              value={proofLink}
              onChange={(e) => setProofLink(e.target.value)}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="outline" onClick={() => setOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" variant="destructive" disabled={loading}>
              {loading ? "Reporting..." : "Report Domain"}
            </Button>
          </div>
        </form>
      </DialogContent>
    </Dialog>
  );
};

export default BlocklistModal;
