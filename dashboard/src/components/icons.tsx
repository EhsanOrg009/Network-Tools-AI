import type { SVGProps } from "react";

/** Hand-drawn 24px stroke icons — one consistent visual language, no icon dep. */
type P = SVGProps<SVGSVGElement> & { size?: number };

function Svg({ size = 19, children, ...rest }: P & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      {...rest}
    >
      {children}
    </svg>
  );
}

export const IconGauge = (p: P) => (
  <Svg {...p}><path d="M12 20a8 8 0 1 1 8-8" /><path d="M12 12l4-3" /><path d="M3.5 20h17" /></Svg>
);
export const IconNodes = (p: P) => (
  <Svg {...p}><rect x="3" y="4" width="6" height="5" rx="1.2" /><rect x="15" y="15" width="6" height="5" rx="1.2" /><rect x="15" y="4" width="6" height="5" rx="1.2" /><path d="M9 6.5h6M6 9v4.5a2 2 0 0 0 2 2h7" /></Svg>
);
export const IconInbox = (p: P) => (
  <Svg {...p}><path d="M4 13h5l2 3h2l2-3h5" /><path d="M5 5h14l2 8v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4l2-8z" /></Svg>
);
export const IconWifi = (p: P) => (
  <Svg {...p}><path d="M2.5 9a14 14 0 0 1 19 0" /><path d="M6 12.5a9 9 0 0 1 12 0" /><path d="M9.5 16a4.5 4.5 0 0 1 5 0" /><circle cx="12" cy="19.4" r="1" fill="currentColor" stroke="none" /></Svg>
);
export const IconShield = (p: P) => (
  <Svg {...p}><path d="M12 3l7.5 3v5.5c0 4.6-3.2 8.2-7.5 9.5-4.3-1.3-7.5-4.9-7.5-9.5V6L12 3z" /><path d="M9.5 12l2 2 3.5-4" /></Svg>
);
export const IconBrain = (p: P) => (
  <Svg {...p}><path d="M9.5 4a2.8 2.8 0 0 0-2.7 3.6A3 3 0 0 0 5 13c0 2 1.5 3.2 3 3.5.1 1.6 1.4 2.9 3 2.9.8 0 1.5-.4 2-1 .5.6 1.2 1 2 1 1.6 0 2.9-1.3 3-2.9 1.5-.3 3-1.5 3-3.5a3 3 0 0 0-1.8-4.4A2.8 2.8 0 0 0 14.5 4c-1 0-2 .5-2.5 1.3C11.5 4.5 10.5 4 9.5 4z" /><path d="M12 5.5V19" /></Svg>
);
export const IconGear = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="3.2" /><path d="M12 3.5v2M12 18.5v2M3.9 7.8l1.7 1M18.4 15.2l1.7 1M3.9 16.2l1.7-1M18.4 7.8l1.7-1M4.5 12H2.5M21.5 12h-2" /></Svg>
);
export const IconAgents = (p: P) => (
  <Svg {...p}><rect x="4" y="7" width="16" height="13" rx="2" /><path d="M9 7V5.5A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5V7" /><path d="M9.5 12h.01M14.5 12h.01" /><path d="M9.5 16c.7.7 1.6 1 2.5 1s1.8-.3 2.5-1" /></Svg>
);
export const IconTerminal = (p: P) => (
  <Svg {...p}><rect x="3" y="4.5" width="18" height="15" rx="2" /><path d="M7 9.5l3 3-3 3" /><path d="M12.5 15.5H17" /></Svg>
);
export const IconSearch = (p: P) => (
  <Svg {...p}><circle cx="11" cy="11" r="6.5" /><path d="M20.5 20.5L16 16" /></Svg>
);
export const IconRefresh = (p: P) => (
  <Svg {...p}><path d="M20 12a8 8 0 1 1-2.5-5.8" /><path d="M20 4v4h-4" /></Svg>
);
export const IconCheck = (p: P) => (
  <Svg {...p}><path d="M4.5 12.5l5 5 10-11" /></Svg>
);
export const IconX = (p: P) => (
  <Svg {...p}><path d="M5 5l14 14M19 5L5 19" /></Svg>
);
export const IconAlert = (p: P) => (
  <Svg {...p}><path d="M12 4l9 16H3l9-16z" /><path d="M12 10.5v4M12 17.5h.01" /></Svg>
);
export const IconSun = (p: P) => (
  <Svg {...p}><circle cx="12" cy="12" r="4" /><path d="M12 2.5v2M12 19.5v2M3.5 12h2M18.5 12h2M5.3 5.3L6.7 6.7M17.3 17.3l1.4 1.4M5.3 18.7l1.4-1.4M17.3 6.7l1.4-1.4" /></Svg>
);
export const IconMoon = (p: P) => (
  <Svg {...p}><path d="M20 13.5A8.5 8.5 0 1 1 10.5 4a7 7 0 0 0 9.5 9.5z" /></Svg>
);
export const IconLogout = (p: P) => (
  <Svg {...p}><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4" /><path d="M10 17l-5-5 5-5M5 12h11" /></Svg>
);
export const IconCopy = (p: P) => (
  <Svg {...p}><rect x="9" y="9" width="11" height="12" rx="2" /><path d="M5 15V5a2 2 0 0 1 2-2h8" /></Svg>
);
export const IconMap = (p: P) => (
  <Svg {...p}><circle cx="6" cy="6" r="2.5" /><circle cx="18" cy="18" r="2.5" /><circle cx="18" cy="7" r="2.2" /><circle cx="9.5" cy="15.5" r="2.2" /><path d="M8 7.5l8-.3M16.6 9l-5.3 4.7M11.6 16.6l4.2 1.2" /></Svg>
);
export const IconOff = (p: P) => (
  <Svg {...p}><path d="M12 3v6" /><path d="M6.3 6.6a9 9 0 1 0 11.4 0" /></Svg>
);
export const IconBook = (p: P) => (
  <Svg {...p}><path d="M5 19.5A2.5 2.5 0 0 1 7.5 17H20V3H7.5A2.5 2.5 0 0 0 5 5.5v14z" /><path d="M5 19.5A2.5 2.5 0 0 0 7.5 22H20v-5" /></Svg>
);
export const IconHeartbeat = (p: P) => (
  <Svg {...p}><path d="M3 12h4l2.5-6 4 12L16 12h5" /></Svg>
);
