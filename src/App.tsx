import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { SeniorModeProvider } from "@/contexts/SeniorModeContext";
import Navbar from "@/components/truthshield/Navbar";
import Index from "./pages/Index";
import Analyze from "./pages/Analyze";
import ImageAnalysisPage from "./pages/ImageAnalysis";
import HistoryPage from "./pages/History";
import DashboardPage from "./pages/Dashboard";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <TooltipProvider>
      <SeniorModeProvider>
        <Toaster />
        <Sonner />
        <BrowserRouter>
          <Navbar />
          <Routes>
            <Route path="/" element={<Index />} />
            <Route path="/analyze" element={<Analyze />} />
            <Route path="/image-analysis" element={<ImageAnalysisPage />} />
            <Route path="/history" element={<HistoryPage />} />
            <Route path="/dashboard" element={<DashboardPage />} />
            <Route path="*" element={<NotFound />} />
          </Routes>
        </BrowserRouter>
      </SeniorModeProvider>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
