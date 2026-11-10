import { brandFonts } from "../fonts";
import "./landing.css";

export default function MarketingLayout({ children }: LayoutProps<"/">) {
  return (
    <div className={`landing ${brandFonts}`}>
      {children}
    </div>
  );
}
