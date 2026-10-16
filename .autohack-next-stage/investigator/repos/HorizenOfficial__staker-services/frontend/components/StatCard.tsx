export function StatCard({
  label,
  value,
  unit,
  hint,
  footer,
  tone = "default",
}: {
  label: string;
  value: React.ReactNode;
  unit?: string;
  hint?: string;
  footer?: React.ReactNode;
  tone?: "default" | "gold";
}) {
  return (
    <div
      className="hl-card"
      style={{
        padding: "var(--hl-space-8)",
        display: "flex",
        flexDirection: "column",
        height: "100%",
      }}
    >
      <div className="hl-label" style={{ marginBottom: "var(--hl-space-3)" }}>
        {label}
      </div>
      <div
        style={{
          fontSize: 28,
          fontWeight: 700,
          lineHeight: 1.1,
          letterSpacing: "-0.01em",
          color: tone === "gold" ? "var(--hl-gold-bright)" : "var(--hl-navy-hover)",
        }}
      >
        {value}
      </div>
      {/* unit and hint sit on their own line below the value so the unit never
          wraps onto the number; aligned consistently across all cards */}
      {unit && (
        <div style={{ fontSize: 12.5, fontWeight: 500, color: "var(--hl-grey-text)", marginTop: 8 }}>{unit}</div>
      )}
      {hint && (
        <div style={{ fontSize: 13, color: "var(--hl-grey-text)", marginTop: 8 }}>{hint}</div>
      )}
      {/* footer anchored to the bottom so action buttons align across cards
          regardless of differing content height */}
      {footer && <div style={{ marginTop: "auto", paddingTop: "var(--hl-space-6)" }}>{footer}</div>}
    </div>
  );
}
