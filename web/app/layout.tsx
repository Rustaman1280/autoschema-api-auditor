import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AutoSchema & API Auditor | Autonomous Security & Performance Engineer",
  description: "End-to-End Autonomous Database Schema & API Security/Performance Auditor powered by Nebius Token Factory, NVIDIA Nemotron, and Tavily Search.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className="bg-slate-950 text-slate-100 min-h-screen">
        {children}
      </body>
    </html>
  );
}
