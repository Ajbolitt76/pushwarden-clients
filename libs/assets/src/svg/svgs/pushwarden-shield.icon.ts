import { svg } from "../svg";

// Full-color PushWarden app icon (fork rebrand); see /branding/pushwarden.svg.
export const PushWardenShield = svg`
  <svg viewBox="0 0 512 512" xmlns="http://www.w3.org/2000/svg">
    <title>PushWarden</title>
    <defs>
      <mask id="pushwarden-icon-check">
        <rect width="512" height="512" style="fill: var(--color-white)" />
        <path d="M192 252 L238 298 L324 208" fill="none" style="stroke: var(--color-black)" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" />
      </mask>
    </defs>
    <rect width="512" height="512" rx="112" style="fill: var(--color-brand-700)" />
    <g mask="url(#pushwarden-icon-check)">
      <path d="M 256.0 84 C 312.0 100 361.3 108 403.8 108 C 410.6 170 408.3 240 394.9 290 C 372.5 360 305.3 404 256.0 428 C 206.7 404 139.5 360 117.1 290 C 103.7 240 101.4 170 108.2 108 C 150.7 108 200.0 100 256.0 84 Z" style="fill: var(--color-white)" />
      <path d="M 256.0 84 C 312.0 100 361.3 108 403.8 108 C 410.6 170 408.3 240 394.9 290 C 372.5 360 305.3 404 256.0 428 Z" style="fill: var(--color-brand-200)" />
    </g>
  </svg>
`;
