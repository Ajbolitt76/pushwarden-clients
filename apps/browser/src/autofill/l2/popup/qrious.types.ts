// Ambient types for qrious, imported for its side effect. Minimal: only what we use.
// qrious (already a dependency of the monorepo; used by the web vault too).
declare module "qrious" {
  interface QRiousOptions {
    element: HTMLCanvasElement;
    value: string;
    size?: number;
    level?: "L" | "M" | "Q" | "H";
  }
  export default class QRious {
    constructor(options: QRiousOptions);
  }
}
