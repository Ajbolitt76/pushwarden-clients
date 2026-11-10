import { svg } from "../svg";

// PushWarden wordmark (fork rebrand); see /branding/pushwarden.svg.
export const BitwardenLogo = svg`
  <svg viewBox="0 0 290 45" xmlns="http://www.w3.org/2000/svg">
    <title>PushWarden</title>
    <defs>
      <mask id="pushwarden-wordmark-check">
        <rect width="512" height="512" style="fill: var(--color-white)" />
        <path d="M192 252 L238 298 L324 208" fill="none" style="stroke: var(--color-black)" stroke-width="40" stroke-linecap="round" stroke-linejoin="round" />
      </mask>
    </defs>
    <g class="tw-fill-marketing-logo">
      <svg x="0" y="0" width="45" height="45" viewBox="84 84 344 344">
        <path mask="url(#pushwarden-wordmark-check)" d="M 256.0 84 C 312.0 100 361.3 108 403.8 108 C 410.6 170 408.3 240 394.9 290 C 372.5 360 305.3 404 256.0 428 C 206.7 404 139.5 360 117.1 290 C 103.7 240 101.4 170 108.2 108 C 150.7 108 200.0 100 256.0 84 Z" />
      </svg>
      <text x="54" y="34" font-family="Inter, Roboto, Helvetica, Arial, sans-serif" font-size="32" font-weight="700" letter-spacing="-0.5">PushWarden</text>
    </g>
  </svg>
`;
