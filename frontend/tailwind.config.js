/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: 'var(--background)',
        foreground: 'var(--foreground)',
        muted: 'var(--muted)',
        muted2: 'var(--muted2)',
        muted3: 'var(--muted3)',
        primary: 'var(--primary)',
      },
    },
  },
  plugins: [],
}
