"use client";

// A styled info tooltip (replaces a bare title="" attribute): the "i" badge
// reveals a small bubble on hover, and on focus so it also works via
// keyboard nav and mobile tap (focusing a tabbable element counts as
// :focus-within on the wrapper).
export function InfoTooltip({ text }: { text: string }) {
  return (
    <span className="hl-tooltip" tabIndex={0} aria-label={text}>
      <span className="hl-info" aria-hidden="true">
        i
      </span>
      <span className="hl-tooltip-bubble" aria-hidden="true">
        {text}
      </span>
    </span>
  );
}
