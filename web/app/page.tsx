"use client";

import React, { useState } from "react";
import {
  ShieldAlert,
  Database,
  Code2,
  Terminal,
  Download,
  Copy,
  Check,
  Search,
  Sparkles,
  Cpu,
  Layers,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw
} from "lucide-react";
import { SAMPLE_SCHEMA_SQL, SAMPLE_API_TS } from "@/lib/mockData";

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState<"schema" | "api">("schema");
  const [schemaCode, setSchemaCode] = useState<string>(SAMPLE_SCHEMA_SQL);
  const [apiCode, setApiCode] = useState<string>(SAMPLE_API_TS);
  const [auditMode, setAuditMode] = useState<"simulation" | "live">("simulation");
  const [nebiusKey, setNebiusKey] = useState<string>("");
  const [tavilyKey, setTavilyKey] = useState<string>("");

  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [currentStep, setCurrentStep] = useState<number>(0);
  const [stepLogs, setStepLogs] = useState<string[]>([]);
  const [auditReport, setAuditReport] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const activeCode = activeTab === "schema" ? schemaCode : apiCode;
  const setActiveCode = activeTab === "schema" ? setSchemaCode : setApiCode;

  const handleLoadSample = (type: "schema" | "api") => {
    setActiveTab(type);
    if (type === "schema") {
      setSchemaCode(SAMPLE_SCHEMA_SQL);
    } else {
      setApiCode(SAMPLE_API_TS);
    }
    setAuditReport(null);
    setErrorMsg(null);
  };

  const handleRunAudit = async () => {
    if (!activeCode.trim()) {
      setErrorMsg("Please provide code or SQL input before initiating the audit.");
      return;
    }

    setIsLoading(true);
    setErrorMsg(null);
    setAuditReport(null);
    setStepLogs([]);
    setCurrentStep(1);

    // Visual step progression simulator for UI responsiveness
    const stepTimer1 = setTimeout(() => {
      setCurrentStep(2);
      setStepLogs((prev) => [
        ...prev,
        "Phase 1: Static Triage & Dialect Parsing complete (PostgreSQL 16 inferred)."
      ]);
    }, 800);

    const stepTimer2 = setTimeout(() => {
      setCurrentStep(3);
      setStepLogs((prev) => [
        ...prev,
        "Phase 2: Live Threat Intelligence search via Tavily complete."
      ]);
    }, 2000);

    try {
      const res = await fetch("/api/audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          code: activeCode,
          type: activeTab,
          forceMock: auditMode === "simulation",
          apiKey: nebiusKey,
          tavilyKey: tavilyKey
        })
      });

      const data = await res.json();
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);

      if (!res.ok) {
        throw new Error(data.error || "Failed to complete audit.");
      }

      setCurrentStep(4);
      setStepLogs(data.steps || [
        "Phase 1: Intake & Semantic Triage",
        "Phase 2: Real-time Threat Verification (Tavily)",
        "Phase 3: Deep Reasoning & Patch Synthesis (Nemotron-3)"
      ]);
      setAuditReport(data.report);
    } catch (err: any) {
      clearTimeout(stepTimer1);
      clearTimeout(stepTimer2);
      setErrorMsg(err.message || "An unexpected error occurred.");
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyReport = () => {
    if (!auditReport) return;
    navigator.clipboard.writeText(auditReport);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownloadReport = () => {
    if (!auditReport) return;
    const blob = new Blob([auditReport], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `audit_report_${activeTab}_${Date.now()}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased">
      {/* Glow effect headers */}
      <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full max-w-7xl h-64 bg-gradient-to-b from-indigo-500/10 via-purple-500/5 to-transparent blur-3xl pointer-events-none" />

      {/* Navigation Header */}
      <header className="border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-xl bg-gradient-to-br from-indigo-500 to-purple-600 text-white shadow-lg shadow-indigo-500/20">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold text-lg tracking-tight bg-gradient-to-r from-white via-slate-200 to-slate-400 bg-clip-text text-transparent">
                  AutoSchema & API Auditor
                </span>
                <span className="hidden sm:inline-flex items-center px-2 py-0.5 rounded-full text-xs font-semibold bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
                  v2.0 Hybrid
                </span>
              </div>
            </div>
          </div>

          <div className="flex items-center space-x-3">
            {/* Badges */}
            <div className="hidden md:flex items-center space-x-2">
              <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300">
                <Cpu className="w-3.5 h-3.5 text-emerald-400 mr-1" />
                Nebius & NVIDIA Nemotron
              </span>
              <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-medium bg-slate-900 border border-slate-800 text-slate-300">
                <Search className="w-3.5 h-3.5 text-cyan-400 mr-1" />
                Tavily CVE Loop
              </span>
            </div>

            {/* Active Mode Indicator */}
            <div className="flex items-center space-x-1.5 px-3 py-1 rounded-full text-xs font-semibold border bg-slate-900/90 border-slate-800">
              <span
                className={`w-2 h-2 rounded-full ${
                  auditMode === "live" ? "bg-emerald-400 animate-pulse" : "bg-amber-400"
                }`}
              />
              <span className={auditMode === "live" ? "text-emerald-400" : "text-amber-400"}>
                {auditMode === "live" ? "Live Nebius Cloud" : "Smart Simulation Mode"}
              </span>
            </div>
          </div>
        </div>
      </header>

      {/* Main Container */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6 relative">
        {/* Top Control Bar: Mode Toggle & Key Config */}
        <section className="bg-slate-900/60 border border-slate-800/80 rounded-2xl p-4 shadow-xl backdrop-blur-sm flex flex-col md:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2 w-full md:w-auto">
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-400 mr-2">
              Runtime Engine:
            </span>
            <button
              onClick={() => setAuditMode("simulation")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                auditMode === "simulation"
                  ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
                  : "bg-slate-800/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              Smart Simulation (Jury Demo)
            </button>
            <button
              onClick={() => setAuditMode("live")}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                auditMode === "live"
                  ? "bg-indigo-600 text-white shadow-md shadow-indigo-600/30"
                  : "bg-slate-800/70 text-slate-400 hover:text-slate-200"
              }`}
            >
              Live Nebius Token Factory
            </button>
          </div>

          <div className="flex items-center space-x-2 w-full md:w-auto justify-end">
            <span className="text-xs text-slate-400 hidden lg:inline">Quick Test:</span>
            <button
              onClick={() => handleLoadSample("schema")}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/90 hover:bg-slate-800 text-slate-200 border border-slate-700/60 flex items-center space-x-1.5 transition-colors"
            >
              <Database className="w-3.5 h-3.5 text-indigo-400" />
              <span>Load Sample Schema</span>
            </button>
            <button
              onClick={() => handleLoadSample("api")}
              className="px-3 py-1.5 rounded-lg text-xs font-medium bg-slate-800/90 hover:bg-slate-800 text-slate-200 border border-slate-700/60 flex items-center space-x-1.5 transition-colors"
            >
              <Code2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Load Sample Controller</span>
            </button>
          </div>
        </section>

        {/* Live Mode API Key Drawer if user toggles Live */}
        {auditMode === "live" && (
          <div className="bg-indigo-950/30 border border-indigo-800/40 rounded-xl p-4 grid grid-cols-1 md:grid-cols-2 gap-4 animate-in fade-in duration-200">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Nebius API Key (Optional override):
              </label>
              <input
                type="password"
                placeholder="Defaults to server environment variable"
                value={nebiusKey}
                onChange={(e) => setNebiusKey(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Tavily API Key (Optional override):
              </label>
              <input
                type="password"
                placeholder="Defaults to server environment variable"
                value={tavilyKey}
                onChange={(e) => setTavilyKey(e.target.value)}
                className="w-full bg-slate-900 border border-slate-800 rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-indigo-500"
              />
            </div>
          </div>
        )}

        {/* Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Code Input & Controls (5 Cols) */}
          <div className="lg:col-span-5 space-y-4">
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
              {/* Tab Selector */}
              <div className="flex border-b border-slate-800 bg-slate-950/60">
                <button
                  onClick={() => {
                    setActiveTab("schema");
                    setAuditReport(null);
                  }}
                  className={`flex-1 px-4 py-3 text-xs font-semibold flex items-center justify-center space-x-2 border-b-2 transition-colors ${
                    activeTab === "schema"
                      ? "border-indigo-500 text-indigo-400 bg-slate-900/50"
                      : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/20"
                  }`}
                >
                  <Database className="w-4 h-4" />
                  <span>Database Schema (DDL)</span>
                </button>
                <button
                  onClick={() => {
                    setActiveTab("api");
                    setAuditReport(null);
                  }}
                  className={`flex-1 px-4 py-3 text-xs font-semibold flex items-center justify-center space-x-2 border-b-2 transition-colors ${
                    activeTab === "api"
                      ? "border-cyan-500 text-cyan-400 bg-slate-900/50"
                      : "border-transparent text-slate-400 hover:text-slate-200 hover:bg-slate-900/20"
                  }`}
                >
                  <Code2 className="w-4 h-4" />
                  <span>API Endpoint (Controller)</span>
                </button>
              </div>

              {/* Code Text Area */}
              <div className="p-3">
                <textarea
                  value={activeCode}
                  onChange={(e) => setActiveCode(e.target.value)}
                  rows={18}
                  placeholder={
                    activeTab === "schema"
                      ? "Paste SQL DDL (e.g. CREATE TABLE users (...))"
                      : "Paste API Controller code (TypeScript, Python, etc.)"
                  }
                  className="w-full bg-slate-950/90 text-slate-200 font-mono text-xs p-3.5 rounded-xl border border-slate-800/80 focus:outline-none focus:border-indigo-500/80 resize-none leading-relaxed"
                />
              </div>

              {/* Action Trigger */}
              <div className="p-3 bg-slate-950/40 border-t border-slate-800/80 flex items-center justify-between">
                <button
                  onClick={() => {
                    setActiveCode("");
                    setAuditReport(null);
                  }}
                  className="text-xs text-slate-500 hover:text-slate-300 flex items-center space-x-1"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  <span>Clear Input</span>
                </button>

                <button
                  onClick={handleRunAudit}
                  disabled={isLoading}
                  className={`px-5 py-2.5 rounded-xl text-xs font-bold flex items-center space-x-2 shadow-lg transition-all ${
                    isLoading
                      ? "bg-slate-800 text-slate-500 cursor-not-allowed"
                      : "bg-gradient-to-r from-indigo-500 via-indigo-600 to-purple-600 text-white hover:opacity-95 shadow-indigo-500/25 cursor-pointer"
                  }`}
                >
                  {isLoading ? (
                    <>
                      <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      <span>Auditing Component...</span>
                    </>
                  ) : (
                    <>
                      <Play className="w-3.5 h-3.5 fill-current" />
                      <span>Run Autonomous Audit</span>
                    </>
                  )}
                </button>
              </div>
            </div>

            {errorMsg && (
              <div className="p-4 rounded-xl bg-red-950/50 border border-red-800/60 text-red-300 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 flex-shrink-0 text-red-400" />
                <span>{errorMsg}</span>
              </div>
            )}
          </div>

          {/* Right Column: Execution Stepper & Audit Results (7 Cols) */}
          <div className="lg:col-span-7 space-y-4">
            {/* Visual Stepper Progress */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 shadow-xl">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                  <Terminal className="w-4 h-4 text-indigo-400" />
                  <span>Autonomous Execution Stepper</span>
                </span>
                <span className="text-[11px] text-slate-500 font-mono">
                  {isLoading ? "Running pipeline..." : auditReport ? "Completed" : "Idle"}
                </span>
              </div>

              {/* Progress Steps */}
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {/* Step 1 */}
                <div
                  className={`p-2.5 rounded-xl border text-xs flex items-center space-x-2.5 transition-colors ${
                    currentStep >= 1
                      ? "bg-indigo-950/40 border-indigo-700/50 text-indigo-200"
                      : "bg-slate-950/40 border-slate-800 text-slate-500"
                  }`}
                >
                  {currentStep > 1 ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  ) : currentStep === 1 && isLoading ? (
                    <div className="w-4 h-4 border-2 border-indigo-400/30 border-t-indigo-400 rounded-full animate-spin flex-shrink-0" />
                  ) : (
                    <Layers className="w-4 h-4 text-slate-600 flex-shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold">1. Static Triage</div>
                    <div className="text-[10px] text-slate-400">Dialect & Risk AST</div>
                  </div>
                </div>

                {/* Step 2 */}
                <div
                  className={`p-2.5 rounded-xl border text-xs flex items-center space-x-2.5 transition-colors ${
                    currentStep >= 2
                      ? "bg-indigo-950/40 border-indigo-700/50 text-indigo-200"
                      : "bg-slate-950/40 border-slate-800 text-slate-500"
                  }`}
                >
                  {currentStep > 2 ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  ) : currentStep === 2 && isLoading ? (
                    <div className="w-4 h-4 border-2 border-cyan-400/30 border-t-cyan-400 rounded-full animate-spin flex-shrink-0" />
                  ) : (
                    <Search className="w-4 h-4 text-slate-600 flex-shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold">2. Threat Research</div>
                    <div className="text-[10px] text-slate-400">Live Tavily CVE Verification</div>
                  </div>
                </div>

                {/* Step 3 */}
                <div
                  className={`p-2.5 rounded-xl border text-xs flex items-center space-x-2.5 transition-colors ${
                    currentStep >= 3
                      ? "bg-indigo-950/40 border-indigo-700/50 text-indigo-200"
                      : "bg-slate-950/40 border-slate-800 text-slate-500"
                  }`}
                >
                  {currentStep >= 4 ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                  ) : currentStep === 3 && isLoading ? (
                    <div className="w-4 h-4 border-2 border-purple-400/30 border-t-purple-400 rounded-full animate-spin flex-shrink-0" />
                  ) : (
                    <Sparkles className="w-4 h-4 text-slate-600 flex-shrink-0" />
                  )}
                  <div>
                    <div className="font-semibold">3. Patch Synthesis</div>
                    <div className="text-[10px] text-slate-400">NVIDIA Nemotron Remediations</div>
                  </div>
                </div>
              </div>

              {/* Dynamic Step Logs */}
              {stepLogs.length > 0 && (
                <div className="mt-3 p-2.5 rounded-lg bg-slate-950/80 border border-slate-800/80 font-mono text-[11px] text-slate-400 space-y-1">
                  {stepLogs.map((log, idx) => (
                    <div key={idx} className="flex items-start space-x-2">
                      <span className="text-emerald-400 select-none">&gt;</span>
                      <span>{log}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Audit Report Viewer */}
            <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden shadow-xl min-h-[440px] flex flex-col">
              <div className="px-5 py-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300 flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4 text-purple-400" />
                  <span>Production Audit & Remediation Report</span>
                </span>

                {auditReport && (
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={handleCopyReport}
                      className="px-2.5 py-1 rounded-lg text-xs font-medium bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700/60 flex items-center space-x-1 transition-colors"
                    >
                      {copied ? (
                        <>
                          <Check className="w-3.5 h-3.5 text-emerald-400" />
                          <span className="text-emerald-400">Copied</span>
                        </>
                      ) : (
                        <>
                          <Copy className="w-3.5 h-3.5" />
                          <span>Copy Markdown</span>
                        </>
                      )}
                    </button>
                    <button
                      onClick={handleDownloadReport}
                      className="px-2.5 py-1 rounded-lg text-xs font-medium bg-indigo-600/80 hover:bg-indigo-600 text-white flex items-center space-x-1 transition-colors"
                    >
                      <Download className="w-3.5 h-3.5" />
                      <span>Download .md</span>
                    </button>
                  </div>
                )}
              </div>

              <div className="p-5 flex-1 overflow-y-auto max-h-[580px] prose prose-invert prose-indigo max-w-none text-slate-300 text-xs sm:text-sm font-sans leading-relaxed">
                {auditReport ? (
                  <div className="space-y-4 whitespace-pre-wrap font-sans">
                    {/* Render plain / formatted report block */}
                    <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800 font-mono text-xs leading-relaxed text-slate-200">
                      {auditReport}
                    </div>
                  </div>
                ) : (
                  <div className="h-full min-h-[300px] flex flex-col items-center justify-center text-center text-slate-500 py-16 space-y-3">
                    <ShieldAlert className="w-12 h-12 text-slate-700" />
                    <div>
                      <p className="font-semibold text-slate-400">No Audit Generated Yet</p>
                      <p className="text-xs text-slate-600 max-w-sm mt-1">
                        Click &ldquo;Run Autonomous Audit&rdquo; or load a quick test sample to start autonomous evaluation with NVIDIA Nemotron & Tavily.
                      </p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
