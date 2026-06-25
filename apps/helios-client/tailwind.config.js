/** @type {import('tailwindcss').Config} */
// Thème repris de l'app web de heliosd (web/tailwind.config.js) pour la cohérence
// visuelle de l'identité Helios — soleil ambre + réseau cyber cyan/magenta.
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        mono: [
          'Cascadia Code', 'JetBrains Mono', 'Fira Code',
          'Consolas', 'ui-monospace', 'SFMono-Regular', 'monospace',
        ],
      },
      colors: {
        sun: { DEFAULT: '#fbbf24', deep: '#d97706' },
        node: { DEFAULT: '#22d3ee', soft: '#67e8f9' },
        flux: { DEFAULT: '#e879f9', soft: '#f0abfc' },
      },
      boxShadow: {
        'neon-cyan': '0 0 18px -2px rgba(34,211,238,0.45), 0 0 40px -10px rgba(34,211,238,0.25)',
        'neon-emerald': '0 0 18px -2px rgba(40,228,160,0.45), 0 0 40px -10px rgba(40,228,160,0.25)',
        'neon-amber': '0 0 18px -2px rgba(251,191,36,0.45), 0 0 50px -10px rgba(251,191,36,0.25)',
        panel: '0 10px 40px -14px rgba(0,0,0,0.55), inset 0 1px 0 rgba(120,200,255,0.06)',
      },
      keyframes: {
        'glow-emerald': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(40,228,160,0.10), 0 0 60px rgba(40,228,160,0.05)' },
          '50%': { boxShadow: '0 0 32px rgba(40,228,160,0.22), 0 0 80px rgba(40,228,160,0.10)' },
        },
        pulse: {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.4' },
        },
      },
      animation: {
        'glow-emerald': 'glow-emerald 3s ease-in-out infinite',
        'pulse-slow': 'pulse 1.6s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
