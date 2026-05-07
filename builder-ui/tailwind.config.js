/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        ink: {
          950: '#05080d',
          900: '#0a0e16',
          800: '#0f1420',
          700: '#161d2e',
          600: '#1f2940',
          500: '#2d3a55',
        },
        cyan: {
          glow: '#22d3ee',
        },
      },
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
      },
      boxShadow: {
        'glow': '0 0 24px -4px rgba(34, 211, 238, 0.4)',
      },
    },
  },
  plugins: [],
};
