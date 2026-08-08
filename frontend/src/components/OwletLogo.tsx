interface Props {
  /** Height in px — width scales automatically (SVG viewBox 540×180) */
  height?: number;
  style?: React.CSSProperties;
  className?: string;
}

export default function OwletLogo({ height = 40, style, className }: Props) {
  const width = Math.round(height * (540 / 180));
  return (
    <img
      src="/owlet-logo.svg"
      alt="Owlet"
      width={width}
      height={height}
      style={{ display: "block", ...style }}
      className={className}
    />
  );
}
