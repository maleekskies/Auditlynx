/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        base: '#0B0E14',
        surface: '#12161F',
        surface2: '#181D29',
        border: '#232838',
        borderLight: '#2E3547',
        ink: '#E4E7EE',
        muted: '#8891A3',
        accent: '#4C8DFF',
        accentDim: '#2E4C8C',
        risk: {
          high: '#E5484D',
          medium: '#F5A623',
          low: '#5B8DEF',
          pass: '#3DD68C',
        },
      },
      fontFamily: {
        display: ['"Space Grotesk"', 'sans-serif'],
        body: ['"Inter"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
      },
    },
  },
  plugins: [],
}
