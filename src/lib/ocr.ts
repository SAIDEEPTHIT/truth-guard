// Lightweight client-side OCR helper using tesseract.js (lazy-loaded).
// Preprocesses images (grayscale + contrast + upscale small images) for
// better Tesseract accuracy on screenshots of SMS / WhatsApp / bank alerts.
import { createWorker } from "tesseract.js";

let workerPromise: Promise<any> | null = null;

async function getWorker() {
  if (!workerPromise) {
    workerPromise = createWorker("eng", 1, {
      // logger: m => console.log(m),
    });
  }
  return workerPromise;
}

export interface OCRResult {
  text: string;
  confidence: number;
  durationMs: number;
}

// ── Preprocessing: grayscale + contrast boost + upscale tiny images ──────────
const MIN_WIDTH = 900;     // upscale narrow screenshots
const CONTRAST = 1.4;      // 1.0 = no change

async function loadImage(file: File | Blob): Promise<HTMLImageElement> {
  const url = URL.createObjectURL(file);
  try {
    return await new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => resolve(img);
      img.onerror = reject;
      img.src = url;
    });
  } finally {
    // Revoke after a tick so the browser actually decoded the bytes.
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
}

async function preprocess(file: File | Blob): Promise<HTMLCanvasElement | Blob> {
  try {
    const img = await loadImage(file);
    let w = img.naturalWidth || img.width;
    let h = img.naturalHeight || img.height;
    if (!w || !h) return file;

    // Upscale small images so Tesseract has more pixels to work with.
    const scale = w < MIN_WIDTH ? MIN_WIDTH / w : 1;
    w = Math.round(w * scale);
    h = Math.round(h * scale);

    const canvas = document.createElement("canvas");
    canvas.width = w;
    canvas.height = h;
    const ctx = canvas.getContext("2d");
    if (!ctx) return file;
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = "high";
    ctx.drawImage(img, 0, 0, w, h);

    // Grayscale + contrast stretch around mid-gray.
    const data = ctx.getImageData(0, 0, w, h);
    const px = data.data;
    const c = CONTRAST;
    const intercept = 128 * (1 - c);
    for (let i = 0; i < px.length; i += 4) {
      const gray = 0.299 * px[i] + 0.587 * px[i + 1] + 0.114 * px[i + 2];
      let v = c * gray + intercept;
      if (v < 0) v = 0;
      else if (v > 255) v = 255;
      px[i] = px[i + 1] = px[i + 2] = v;
    }
    ctx.putImageData(data, 0, 0);
    return canvas;
  } catch (err) {
    console.warn("[OCR] preprocessing failed, using original:", err);
    return file;
  }
}

export async function extractTextFromImage(file: File | Blob): Promise<OCRResult> {
  const start = performance.now();
  try {
    const worker = await getWorker();
    const processed = await preprocess(file);
    const { data } = await worker.recognize(processed as any);
    return {
      text: (data.text || "").trim(),
      confidence: Math.round((data.confidence as number) || 0),
      durationMs: Math.round(performance.now() - start),
    };
  } catch (err) {
    console.warn("[OCR] failed:", err);
    return { text: "", confidence: 0, durationMs: Math.round(performance.now() - start) };
  }
}
