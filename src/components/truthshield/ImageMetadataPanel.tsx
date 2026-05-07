import { motion } from "framer-motion";
import { Camera, Calendar, MapPin, FileImage, AlertTriangle, CheckCircle2, Info } from "lucide-react";
import { useSeniorMode } from "@/contexts/SeniorModeContext";

interface MetadataIndicator {
  signal: string;
  detail: string;
  severity: string;
  type: string;
}

interface ImageMetadata {
  filename?: string;
  fileSize?: number;
  fileSizeMB?: number;
  hasMissingEXIF?: boolean;
  cameraMake?: string | null;
  cameraModel?: string | null;
  lensModel?: string | null;
  software?: string | null;
  creationDate?: string | null;
  modifyDate?: string | null;
  iso?: number | string | null;
  aperture?: string | null;
  shutterSpeed?: string | null;
  focalLength?: string | null;
  gpsLatitude?: number | null;
  gpsLongitude?: number | null;
  orientation?: number | null;
  colorSpace?: string | null;
  width?: number | null;
  height?: number | null;
}

interface Props {
  metadata: ImageMetadata;
  metadataScore: number;
  indicators: MetadataIndicator[];
}

const ImageMetadataPanel = ({ metadata, metadataScore, indicators }: Props) => {
  const { seniorMode } = useSeniorMode();

  const getScoreColor = (score: number) => {
    if (score <= 30) return "text-emerald-400";
    if (score <= 60) return "text-yellow-400";
    return "text-red-400";
  };

  const getScoreBg = (score: number) => {
    if (score <= 30) return "bg-emerald-500/20 border-emerald-500/30";
    if (score <= 60) return "bg-yellow-500/20 border-yellow-500/30";
    return "bg-red-500/20 border-red-500/30";
  };

  const getIndicatorIcon = (type: string) => {
    switch (type) {
      case "green": return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
      case "red": return <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />;
      case "yellow": return <Info className="w-4 h-4 text-yellow-400 shrink-0" />;
      default: return <Info className="w-4 h-4 text-muted-foreground shrink-0" />;
    }
  };

  const getIndicatorBg = (type: string) => {
    switch (type) {
      case "green": return "bg-emerald-500/10 border-emerald-500/20";
      case "red": return "bg-red-500/10 border-red-500/20";
      case "yellow": return "bg-yellow-500/10 border-yellow-500/20";
      default: return "bg-muted/50 border-border";
    }
  };

  return (
    <div className="space-y-4">
      {/* Metadata Score */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        className={`rounded-xl border p-4 ${getScoreBg(metadataScore)}`}
      >
        <div className="flex items-center justify-between">
          <span className={`font-semibold ${seniorMode ? "text-base" : "text-sm"}`}>
            Metadata Authenticity Score
          </span>
          <span className={`text-2xl font-bold ${getScoreColor(metadataScore)}`}>
            {metadataScore}/100
          </span>
        </div>
        <div className="mt-2 h-2 rounded-full bg-background/50 overflow-hidden">
          <motion.div
            initial={{ width: 0 }}
            animate={{ width: `${metadataScore}%` }}
            transition={{ duration: 0.8, ease: "easeOut" }}
            className={`h-full rounded-full ${
              metadataScore <= 30 ? "bg-emerald-500" : metadataScore <= 60 ? "bg-yellow-500" : "bg-red-500"
            }`}
          />
        </div>
      </motion.div>

      {/* Camera Info */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <Camera className="w-4 h-4" /> Camera Information
        </h3>
        <div className="space-y-2">
          <MetaRow label="Camera Make" value={metadata.cameraMake} />
          <MetaRow label="Camera Model" value={metadata.cameraModel} />
          <MetaRow label="Lens" value={metadata.lensModel} />
          <MetaRow label="ISO" value={metadata.iso} />
          <MetaRow label="Aperture" value={metadata.aperture} />
          <MetaRow label="Shutter Speed" value={metadata.shutterSpeed} />
          <MetaRow label="Focal Length" value={metadata.focalLength} />
        </div>
      </motion.div>

      {/* Creation Info */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <Calendar className="w-4 h-4" /> Image Creation
        </h3>
        <div className="space-y-2">
          <MetaRow label="Date Created" value={metadata.creationDate} />
          <MetaRow label="Software" value={metadata.software} />
          {metadata.gpsLatitude != null && (
            <div className="flex items-center gap-2 mt-2 p-2 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
              <MapPin className="w-4 h-4 text-yellow-400" />
              <span className="text-xs text-yellow-400">
                GPS: {metadata.gpsLatitude?.toFixed(4)}, {metadata.gpsLongitude?.toFixed(4)} ⚠️ Privacy
              </span>
            </div>
          )}
        </div>
      </motion.div>

      {/* Image Properties */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <FileImage className="w-4 h-4" /> Image Properties
        </h3>
        <div className="space-y-2">
          <MetaRow label="Resolution" value={metadata.width && metadata.height ? `${metadata.width} × ${metadata.height}` : null} />
          <MetaRow label="Color Space" value={metadata.colorSpace} />
          <MetaRow label="File Size" value={metadata.fileSizeMB != null ? `${metadata.fileSizeMB} MB` : null} />
          <MetaRow label="Orientation" value={metadata.orientation} />
        </div>
      </motion.div>

      {/* Analysis Indicators */}
      <motion.div
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.4 }}
        className="rounded-xl border border-border bg-card p-4"
      >
        <h3 className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-muted-foreground mb-3">
          <AlertTriangle className="w-4 h-4" /> Analysis Indicators
        </h3>
        <div className="space-y-2">
          {indicators.map((ind, i) => (
            <motion.div
              key={i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: 0.4 + i * 0.05 }}
              className={`flex items-start gap-2.5 p-2.5 rounded-lg border ${getIndicatorBg(ind.type)}`}
            >
              {getIndicatorIcon(ind.type)}
              <div>
                <p className={`font-medium ${seniorMode ? "text-sm" : "text-xs"}`}>{ind.signal}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{ind.detail}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </motion.div>
    </div>
  );
};

const MetaRow = ({ label, value }: { label: string; value: string | number | null | undefined }) => (
  <div className="flex justify-between items-center text-sm">
    <span className="text-muted-foreground">{label}</span>
    <span className={`font-mono text-xs ${value ? "" : "text-muted-foreground/50 italic"}`}>
      {value ?? "N/A"}
    </span>
  </div>
);

export default ImageMetadataPanel;
