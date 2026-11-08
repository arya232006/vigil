import { brandFonts } from "../fonts";
import "./landing.css";
import { SmoothScroll } from "./SmoothScroll";

export default function MarketingLayout({ children }: LayoutProps<"/">) {
  return (
    <div className={`landing ${brandFonts}`}>
      <SmoothScroll />
      {children}
    </div>
  );
}
