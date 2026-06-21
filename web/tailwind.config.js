/** @type {import('tailwindcss').Config} */
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
        // Identité Helios : soleil ambre + réseau cyber cyan/magenta
        sun:    { DEFAULT: '#fbbf24', deep: '#d97706' },
        node:   { DEFAULT: '#22d3ee', soft: '#67e8f9' }, // cyan
        flux:   { DEFAULT: '#e879f9', soft: '#f0abfc' }, // magenta
      },
      boxShadow: {
        'neon-cyan':    '0 0 18px -2px rgba(34,211,238,0.45), 0 0 40px -10px rgba(34,211,238,0.25)',
        'neon-fuchsia': '0 0 18px -2px rgba(232,121,249,0.40), 0 0 40px -10px rgba(232,121,249,0.22)',
        'neon-amber':   '0 0 18px -2px rgba(251,191,36,0.45), 0 0 50px -10px rgba(251,191,36,0.25)',
        'panel':        '0 10px 40px -14px rgba(0,0,0,0.55), inset 0 1px 0 rgba(120,200,255,0.06)',
      },
      keyframes: {
        'glow-emerald': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(16,185,129,0.08), 0 0 60px rgba(16,185,129,0.04)' },
          '50%':        { boxShadow: '0 0 30px rgba(16,185,129,0.18), 0 0 80px rgba(16,185,129,0.08)' },
        },
        'glow-cyan': {
          '0%, 100%': { boxShadow: '0 0 20px rgba(34,211,238,0.10), 0 0 60px rgba(34,211,238,0.05)' },
          '50%':        { boxShadow: '0 0 32px rgba(34,211,238,0.22), 0 0 80px rgba(34,211,238,0.10)' },
        },
        'scan': {
          '0%':   { transform: 'translateY(-100%)', opacity: '0' },
          '50%':  { opacity: '0.6' },
          '100%': { transform: 'translateY(100%)', opacity: '0' },
        },
        'float-up': {
          '0%':   { opacity: '0', transform: 'translateY(6px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
      },
      animation: {
        'glow-emerald': 'glow-emerald 3s ease-in-out infinite',
        'glow-cyan':    'glow-cyan 3s ease-in-out infinite',
        'scan':         'scan 4s linear infinite',
        'float-up':     'float-up 0.4s ease-out both',
      },
    },
  },
  plugins: [],
}
