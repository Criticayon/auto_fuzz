# Pipeline Controls Palette Design

## Goal

Restyle only the Pipeline Controls action area so it reads as a painter's
board with colored paint controls. Preserve all existing button IDs,
handlers, disabled behavior, and status text.

## Visual Direction

- Keep the controls container as a warm wooden board, but refine it with a
  framed edge, subtle grain, and inset work surface.
- Render Phase buttons as thick paint swatches with rounded, irregular edges,
  glossy highlights, and a small paint dab detail.
- Preserve the existing phase color mapping:
  - Phase 1: orange
  - Phase 2: green
  - Phase 3: blue
  - Phase 4: violet
  - Phase 5: charcoal
- Render each phase clear action as a compact two-tone eraser directly below
  its paint swatch. The eraser's colored sleeve matches the phase color.
- Render Clean All as a distinct red paint swatch because it is a destructive
  global action; it does not receive a per-phase eraser.

## Interaction

- Hover lifts paint swatches slightly and increases the highlight.
- Pressing compresses the swatch toward the board.
- Erasers tilt slightly on hover and remain clearly disabled when unavailable.
- Focus-visible states remain keyboard accessible.
- Existing tooltips and JavaScript behavior remain unchanged.

## Scope

The implementation is limited to `pipeline/ui/style.css`, with optional
semantic labels in `pipeline/ui/index.html` only if accessibility requires
them. No backend or pipeline behavior changes are included.

## Verification

- Confirm the HTML IDs and click handlers are unchanged.
- Check CSS syntax and inspect the rendered Pipeline page at desktop and a
  narrow viewport.
- Confirm disabled paint buttons and erasers are visually distinct.
