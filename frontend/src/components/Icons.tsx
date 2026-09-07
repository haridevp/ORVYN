interface IconProps {
  className?: string;
  size?: number;
}

const strokeProps = {
  stroke: "currentColor",
  strokeWidth: 1.8,
  strokeLinecap: "round" as const,
  strokeLinejoin: "round" as const,
};

function Svg({ className = "", size = 16, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" aria-hidden="true" className={`shrink-0 ${className}`}>
      {children}
    </svg>
  );
}

export function IconActivity(p?: IconProps) {
  return (
    <Svg {...p}>
      <path d="M22 12h-4l-3 9L9 3l-3 9H2" {...strokeProps} />
    </Svg>
  );
}

export function IconLayers(p?: IconProps) {
  return (
    <Svg {...p}>
      <path d="m12 2 9 5-9 5-9-5 9-5Z" {...strokeProps} />
      <path d="m3 12 9 5 9-5" {...strokeProps} />
      <path d="m3 17 9 5 9-5" {...strokeProps} />
    </Svg>
  );
}

export function IconFlame(p?: IconProps) {
  return (
    <Svg {...p}>
      <path d="M12 2c1 3-2 4-2 7a4 4 0 0 0 8 0c0-1-1-2-1-2 1 4-1 6-3 6a4 4 0 0 1-4-4c0-3 3-4 2-7Z" {...strokeProps} />
    </Svg>
  );
}

export function IconTarget(p?: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="12" cy="12" r="9" {...strokeProps} />
      <circle cx="12" cy="12" r="5" {...strokeProps} />
      <circle cx="12" cy="12" r="1" {...strokeProps} />
    </Svg>
  );
}

export function IconServer(p?: IconProps) {
  return (
    <Svg {...p}>
      <rect x="3" y="4" width="18" height="7" rx="1.5" {...strokeProps} />
      <rect x="3" y="13" width="18" height="7" rx="1.5" {...strokeProps} />
      <path d="M7 7.5h.01M7 16.5h.01" {...strokeProps} />
    </Svg>
  );
}

export function IconPlay(p?: IconProps) {
  return (
    <Svg {...p}>
      <path d="M6 3.5v17l14-8.5-14-8.5Z" fill="currentColor" />
    </Svg>
  );
}

export function IconSearchOff(p?: IconProps) {
  return (
    <Svg {...p}>
      <circle cx="10.5" cy="10.5" r="6.5" {...strokeProps} />
      <path d="m20 20-4.3-4.3" {...strokeProps} />
    </Svg>
  );
}
