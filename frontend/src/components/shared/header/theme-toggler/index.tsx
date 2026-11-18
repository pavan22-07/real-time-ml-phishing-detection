import { Button } from "@/components/ui/button";
import { useTheme } from "@/context/ThemeContext";
import { MoonIcon, SunIcon } from "@/icons";

export default function ThemeToggleButton() {
  const { toggleTheme, theme } = useTheme();

  return (
    <Button
      variant="outline"
      size="icon-lg"
      className="relative border-slate-700 bg-slate-900/60 text-slate-300 hover:bg-slate-800 hover:text-white"
      aria-label="Toggle theme"
      onClick={toggleTheme}
    >
      {theme === "dark" ? <SunIcon className="size-5 text-amber-400" /> : <MoonIcon className="size-5 text-slate-300" />}
    </Button>
  );
}
