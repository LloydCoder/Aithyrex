/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ['./app/**/*.{js,ts,jsx,tsx}', './components/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      colors: {
        bg:       '#060A14',
        card:     '#0D1B2A',
        raised:   '#0F2236',
        cyan:     '#00D4FF',
        'cyan-dim':'#0891B2',
        navy:     '#1E293B',
        muted:    '#94A3B8',
        dim:      '#475569',
      },
      fontFamily: {
        grotesk: ['Space Grotesk', 'sans-serif'],
        mono:    ['JetBrains Mono', 'monospace'],
        sans:    ['Inter', 'sans-serif'],
      },
    },
  },
  plugins: [],
}
