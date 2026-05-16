// Lightweight client-side OCR helper using tesseract.js (lazy-loaded).
// Returns extracted text or empty string on failure.
import { createWorker } from "tesseract.js";

let workerPromise: Promise<any> | null = null;

async function getWorker() {
  if (!workerPromise) {
    workerPromise = createWorker("eng", 1, {
      // No logger to keep console clean; uncomment for debugging.
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

export async function extractTextFromImage(file: File | Blob): Promise<OCRResult> {
  const start = performance.now();
  try {
    const worker = await getWorker();
    const url = URL.createObjectURL(file);
    try {
      const { data } = await worker.recognize(url);
      return {
        text: (data.text || "").trim(),
        confidence: Math.round((data.confidence as number) || 0),
        durationMs: Math.round(performance.now() - start),
      };
    } finally {
      URL.revokeObjectURL(url);
    }
  } catch (err) {
    console.warn("[OCR] failed:", err);
    return { text: "", confidence: 0, durationMs: Math.round(performance.now() - start) };
  }
}
