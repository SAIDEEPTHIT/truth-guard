import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, FileText, ImageIcon, Brain, Users, MapPin, Eye, ArrowRight, Sparkles } from "lucide-react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import { Button } from "@/components/ui/button";

const features = [
  {
    icon: Brain,
    title: "Multi-Factor AI Detection",
    desc: "Combines keyword analysis, stylometric patterns, and heuristic scoring to detect AI-generated content with explainable output.",
  },
  {
    icon: Shield,
    title: "Scam & Phishing Detection",
    desc: "Identifies 60+ scam indicators including phishing phrases, urgency tactics, and fraudulent financial language.",
  },
  {
    icon: MapPin,
    title: "India-Specific Scam Patterns",
    desc: "Detects region-specific fraud patterns: fake KYC, UPI scams, OTP theft, bank impersonation, and job fraud.",
  },
  {
    icon: ImageIcon,
    title: "AI Image Detection",
    desc: "Analyzes images for AI-generation indicators: dimension patterns, color uniformity, EXIF metadata, and pixel smoothness.",
  },
  {
    icon: Eye,
    title: "Senior-Friendly Mode",
    desc: "High-contrast, large-text accessibility mode with simplified risk indicators designed for non-technical users.",
  },
  {
    icon: Sparkles,
    title: "Explainable AI Output",
    desc: "Every flagged phrase comes with a human-readable explanation of WHY it was flagged and what to do about it.",
  },
];

const Landing = () => {
  const { seniorMode } = useSeniorMode();

  return (
    <div className="min-h-screen">
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 grid-pattern opacity-50" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-primary/5 blur-[120px]" />

        <div className="relative max-w-6xl mx-auto px-4 pt-20 pb-24 text-center">
          <motion.div
            initial={{ opacity: 0, y: 30 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
          >
            <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-primary/20 bg-primary/5 text-primary text-sm font-medium mb-8">
              <Shield className="w-4 h-4" />
              Explainable AI-Powered Protection
            </div>

            <h1 className={`font-black leading-tight mb-6 ${seniorMode ? "text-4xl md:text-5xl" : "text-4xl md:text-6xl lg:text-7xl"}`}>
              <span className="text-gradient-cyber">TruthShield</span>
              <br />
              <span className="text-foreground">
                {seniorMode ? "Keeps You Safe Online" : "Detect. Explain. Protect."}
              </span>
            </h1>

            <p className={`max-w-2xl mx-auto text-muted-foreground mb-10 ${seniorMode ? "text-xl leading-relaxed" : "text-lg"}`}>
              {seniorMode
                ? "TruthShield checks if online messages are scams, fake, or made by AI. It tells you exactly WHY something is suspicious and what you should do."
                : "An explainable AI browser extension that detects AI-generated content, scam patterns, and emotional manipulation in online text and images — with region-specific intelligence for Indian users."
              }
            </p>

            <div className="flex flex-wrap items-center justify-center gap-4">
              <Link to="/analyze">
                <Button size="lg" className="gap-2 bg-gradient-cyber hover:opacity-90 text-primary-foreground px-8">
                  <FileText className="w-5 h-5" />
                  {seniorMode ? "Check a Message" : "Analyze Text"}
                </Button>
              </Link>
              <Link to="/image-analysis">
                <Button size="lg" variant="outline" className="gap-2 px-8">
                  <ImageIcon className="w-5 h-5" />
                  {seniorMode ? "Check a Photo" : "Analyze Image"}
                </Button>
              </Link>
            </div>
          </motion.div>

          {/* Stats */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
            className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-16 max-w-3xl mx-auto"
          >
            {[
              { value: "90+", label: "Scam Patterns" },
              { value: "25+", label: "AI Indicators" },
              { value: "23+", label: "India-Specific" },
              { value: "100%", label: "Explainable" },
            ].map((stat, i) => (
              <div key={i} className="p-4 rounded-lg border border-border bg-card/50">
                <div className="text-2xl font-bold font-mono text-primary">{stat.value}</div>
                <div className="text-xs text-muted-foreground mt-1">{stat.label}</div>
              </div>
            ))}
          </motion.div>
        </div>
      </section>

      {/* Features Grid */}
      <section className="py-20 border-t border-border">
        <div className="max-w-6xl mx-auto px-4">
          <div className="text-center mb-14">
            <h2 className={`font-bold mb-3 ${seniorMode ? "text-3xl" : "text-3xl"}`}>
              {seniorMode ? "How TruthShield Protects You" : "Key Features"}
            </h2>
            <p className="text-muted-foreground max-w-xl mx-auto">
              Multi-layered analysis combining NLP heuristics, stylometric analysis, and region-specific intelligence.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-5">
            {features.map((feature, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.1 }}
                className="p-6 rounded-xl border border-border bg-card hover:border-primary/30 hover:shadow-glow-primary transition-all group"
              >
                <div className="w-10 h-10 rounded-lg bg-primary/10 flex items-center justify-center mb-4 group-hover:bg-gradient-cyber transition-colors">
                  <feature.icon className="w-5 h-5 text-primary group-hover:text-primary-foreground" />
                </div>
                <h3 className="font-semibold mb-2">{feature.title}</h3>
                <p className={`text-muted-foreground ${seniorMode ? "text-base" : "text-sm"}`}>{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* How it works */}
      <section className="py-20 border-t border-border">
        <div className="max-w-4xl mx-auto px-4">
          <h2 className="text-3xl font-bold text-center mb-14">
            {seniorMode ? "How It Works (Simple Steps)" : "How It Works"}
          </h2>

          <div className="space-y-6">
            {[
              {
                step: "1",
                title: seniorMode ? "Copy the suspicious message" : "Select or Paste Content",
                desc: seniorMode
                  ? "Copy the text you received (WhatsApp, email, SMS) and paste it in TruthShield."
                  : "Highlight text on any webpage or paste it directly into the analyzer. Upload images for visual content analysis.",
              },
              {
                step: "2",
                title: seniorMode ? "TruthShield checks it for you" : "Multi-Factor Analysis",
                desc: seniorMode
                  ? "We check for scam tricks, AI-written content, and pressure tactics that try to make you act without thinking."
                  : "Our engine runs 90+ pattern checks across scam keywords, emotional manipulation, AI-generation signatures, stylometric analysis, and India-specific fraud patterns.",
              },
              {
                step: "3",
                title: seniorMode ? "Get a clear, easy answer" : "Explainable Results",
                desc: seniorMode
                  ? "You get a simple Safe/Suspicious/Dangerous result with clear explanations of WHY and what to do next."
                  : "Receive a Risk Index score (0-100), classification, highlighted suspicious phrases, per-indicator explanations, and actionable safety tips.",
              },
            ].map((item, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -20 }}
                whileInView={{ opacity: 1, x: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.15 }}
                className="flex gap-5 p-5 rounded-xl border border-border bg-card"
              >
                <div className="w-12 h-12 rounded-full bg-gradient-cyber flex items-center justify-center text-primary-foreground font-bold text-lg shrink-0">
                  {item.step}
                </div>
                <div>
                  <h3 className="font-semibold text-lg mb-1">{item.title}</h3>
                  <p className={`text-muted-foreground ${seniorMode ? "text-base" : "text-sm"}`}>{item.desc}</p>
                </div>
              </motion.div>
            ))}
          </div>

          <div className="text-center mt-12">
            <Link to="/analyze">
              <Button size="lg" className="gap-2 bg-gradient-cyber hover:opacity-90 text-primary-foreground">
                Try It Now <ArrowRight className="w-4 h-4" />
              </Button>
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-10 border-t border-border">
        <div className="max-w-6xl mx-auto px-4 text-center">
          <div className="flex items-center justify-center gap-2 mb-3">
            <Shield className="w-5 h-5 text-primary" />
            <span className="font-bold text-gradient-cyber">TruthShield</span>
          </div>
          <p className="text-xs text-muted-foreground">
            CSP67 Mini Project — Dept. of Computer Science & Engineering, M.S. Ramaiah Institute of Technology
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Shilpa G • Shreenanda S Naik • T Sai Deepthi — Guide: Prof. Priya K
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
