/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./app/templates/**/*.html",
    "./app/api/**/*.py"
  ],
  theme: {
    extend: {
      colors: {
        ops: {
          background: "#080d18",
          panel: "#101827",
          border: "#243247",
          muted: "#8291a7",
          accent: "#38bdf8",
          success: "#22c55e",
          warning: "#f59e0b",
          danger: "#ef4444"
        }
      }
    }
  },
  plugins: []
};