/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', "Menlo", "monospace"],
      },
      colors: {
        terminal: {
          bg: "#0d1117",
          surface: "#161b22",
          border: "#30363d",
          text: "#c9d1d9",
          muted: "#8b949e",
          accent: "#58a6ff",
          green: "#3fb950",
          yellow: "#d29922",
          red: "#f85149",
          orange: "#d18616",
          cyan: "#39d4e0",
        },
      },
    },
  },
  plugins: [],
};
