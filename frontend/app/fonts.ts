import { Inter_Tight, JetBrains_Mono, VT323 } from "next/font/google";

const display = Inter_Tight({ variable: "--font-display", subsets: ["latin"], weight: ["400", "500"] });
const terminal = VT323({ variable: "--font-terminal", subsets: ["latin"], weight: "400" });
const code = JetBrains_Mono({ variable: "--font-code", subsets: ["latin"], weight: ["300", "400"] });

/** Font variables used by the branded surfaces (`.landing`). */
export const brandFonts = `${display.variable} ${terminal.variable} ${code.variable}`;
