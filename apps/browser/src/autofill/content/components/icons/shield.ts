import { css } from "@emotion/css";
import { html } from "lit";

import { IconProps } from "../common-types";
import { buildIconColorRule, ruleNames, themes } from "../constants/styles";

// PushWarden shield with the check cut out; see /branding/pushwarden.svg.
export function Shield({ ariaHidden = true, color, theme }: IconProps) {
  const shapeColor = color || themes[theme].brandLogo;

  return html`
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="100 80 312 352"
      fill="none"
      aria-hidden="${ariaHidden}"
    >
      <mask id="pushwarden-shield-check">
        <rect x="0" y="0" width="512" height="512" fill="#fff" />
        <path
          d="M192 252 L238 298 L324 208"
          fill="none"
          stroke="#000"
          stroke-width="40"
          stroke-linecap="round"
          stroke-linejoin="round"
        />
      </mask>
      <path
        class=${css(buildIconColorRule(shapeColor, ruleNames.fill))}
        mask="url(#pushwarden-shield-check)"
        d="M 256.0 84 C 312.0 100 361.3 108 403.8 108 C 410.6 170 408.3 240 394.9 290 C 372.5 360 305.3 404 256.0 428 C 206.7 404 139.5 360 117.1 290 C 103.7 240 101.4 170 108.2 108 C 150.7 108 200.0 100 256.0 84 Z"
      />
    </svg>
  `;
}
