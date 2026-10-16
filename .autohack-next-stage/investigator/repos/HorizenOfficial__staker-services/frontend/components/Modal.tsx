"use client";

import { useEffect } from "react";

export function Modal({
  title,
  onClose,
  closeable = true,
  showClose = true,
  children,
}: {
  title: string;
  onClose: () => void;
  closeable?: boolean;
  showClose?: boolean;
  children: React.ReactNode;
}) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape" && closeable) onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [closeable, onClose]);

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      onClick={() => closeable && onClose()}
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(4, 23, 66, 0.6)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        padding: 20,
        zIndex: 400,
      }}
    >
      <div className="hl-card" onClick={(e) => e.stopPropagation()} style={{ maxWidth: 440, width: "100%" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: "var(--hl-space-6)" }}>
          <h2 style={{ fontSize: 24 }}>{title}</h2>
          {closeable && showClose && (
            <button
              aria-label="Close"
              onClick={onClose}
              className="hl-mono"
              style={{ background: "none", border: 0, cursor: "pointer", fontSize: 18, color: "var(--hl-grey-text)" }}
            >
              ✕
            </button>
          )}
        </div>
        {children}
      </div>
    </div>
  );
}
