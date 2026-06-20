/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: [
          'Cascadia Code', 'JetBrains Mono', 'Fira Code',
          'Consolas', 'ui-monospace', 'SFMono-Regular', 'monospace',
        ],
      },
      keyframes: {
        'glow-emerald': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(16,185,129,0.08), 0 0 60px rgba(16,185,129,0.04)' },
          '50%':        { boxShadow: '0 0 30px rgba(16,185,129,0.16), 0 0 80px rgba(16,185,129,0.08)' },
        },
      },
      animation: {
        'glow-emerald': 'glow-emerald 3s ease-in-out infinite',
      },
    },
  },
  plugins: [],
}
