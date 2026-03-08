import { Link, useLocation } from "react-router-dom";
import { Shield, Menu, X, Eye } from "lucide-react";
import { useState } from "react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";
import { Switch } from "@/components/ui/switch";

const Navbar = () => {
  const [mobileOpen, setMobileOpen] = useState(false);
  const { seniorMode, toggleSeniorMode } = useSeniorMode();
  const location = useLocation();

  const links = [
    { to: "/", label: "Home" },
    { to: "/analyze", label: "Analyze Text" },
    { to: "/image-analysis", label: "Analyze Image" },
    { to: "/history", label: "History" },
    { to: "/dashboard", label: "Dashboard" },
  ];

  return (
    <nav className="sticky top-0 z-50 glass">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-lg bg-gradient-cyber flex items-center justify-center">
              <Shield className="w-5 h-5 text-primary-foreground" />
            </div>
            <span className="text-lg font-bold text-gradient-cyber">TruthShield</span>
          </Link>

          <div className="hidden md:flex items-center gap-1">
            {links.map(link => (
              <Link
                key={link.to}
                to={link.to}
                className={`px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  location.pathname === link.to
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:text-foreground hover:bg-secondary"
                }`}
              >
                {link.label}
              </Link>
            ))}
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-full border border-border bg-secondary/50">
              <Eye className="w-4 h-4 text-muted-foreground" />
              <span className="text-xs font-medium text-muted-foreground">Senior Mode</span>
              <Switch checked={seniorMode} onCheckedChange={toggleSeniorMode} />
            </div>

            <button
              className="md:hidden p-2 rounded-md text-muted-foreground hover:text-foreground"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>

        {mobileOpen && (
          <div className="md:hidden pb-4 space-y-1">
            {links.map(link => (
              <Link
                key={link.to}
                to={link.to}
                onClick={() => setMobileOpen(false)}
                className={`block px-3 py-2 rounded-md text-sm font-medium ${
                  location.pathname === link.to
                    ? "bg-primary/10 text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {link.label}
              </Link>
            ))}
          </div>
        )}
      </div>
    </nav>
  );
};

export default Navbar;
