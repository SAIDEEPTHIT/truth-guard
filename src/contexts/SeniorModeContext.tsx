import React, { createContext, useContext, useState, useEffect, ReactNode } from "react";

interface SeniorModeContextType {
  seniorMode: boolean;
  toggleSeniorMode: () => void;
}

const SeniorModeContext = createContext<SeniorModeContextType>({
  seniorMode: false,
  toggleSeniorMode: () => {},
});

export const useSeniorMode = () => useContext(SeniorModeContext);

export const SeniorModeProvider = ({ children }: { children: ReactNode }) => {
  const [seniorMode, setSeniorMode] = useState(() => {
    return localStorage.getItem("truthshield_senior_mode") === "true";
  });

  useEffect(() => {
    localStorage.setItem("truthshield_senior_mode", String(seniorMode));
    if (seniorMode) {
      document.documentElement.classList.add("senior-mode");
    } else {
      document.documentElement.classList.remove("senior-mode");
    }
  }, [seniorMode]);

  return (
    <SeniorModeContext.Provider value={{ seniorMode, toggleSeniorMode: () => setSeniorMode(p => !p) }}>
      {children}
    </SeniorModeContext.Provider>
  );
};
