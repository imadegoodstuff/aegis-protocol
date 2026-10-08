import { useEffect } from "react";

/**
 * Lightweight scroll-parallax: sets `--py` on <html> equal to window.scrollY,
 * and `--section-top` on each `.section` equal to its offsetTop. CSS
 * `transform: translateY(calc((var(--py) - var(--section-top)) * -0.1px))` then
 * yields smooth parallax without any JS DOM writes per frame beyond :root.
 *
 * We use requestAnimationFrame-coalesced updates so scroll stays 60fps.
 */
export function useParallax() {
  useEffect(() => {
    const root = document.documentElement;

    const sections = Array.from(document.querySelectorAll<HTMLElement>(".section, .hero"));
    sections.forEach((s) => {
      s.style.setProperty("--section-top", `${s.offsetTop}`);
    });

    const onResize = () => {
      sections.forEach((s) => s.style.setProperty("--section-top", `${s.offsetTop}`));
    };

    let ticking = false;
    const onScroll = () => {
      if (ticking) return;
      ticking = true;
      requestAnimationFrame(() => {
        root.style.setProperty("--py", `${window.scrollY}`);
        ticking = false;
      });
    };

    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    return () => {
      window.removeEventListener("scroll", onScroll);
      window.removeEventListener("resize", onResize);
    };
  }, []);
}
