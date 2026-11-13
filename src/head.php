<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<link rel="icon" type="image/png" href="favicon.png">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Hanken+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
  tailwind.config = {
    theme: {
      extend: {
        fontFamily: { sans: ['"Hanken Grotesk"', 'ui-sans-serif', 'system-ui', 'sans-serif'] },
        colors: {
          mist:   '#E9EEF0',
          ink:    '#14202A',
          slate2: '#5C6B77',
          line:   '#D3DBE0',
          brick:  '#B3372F',
          pine:   { DEFAULT: '#1E6B5A', dark: '#175546' },
        },
      },
    },
  };
</script>
<style type="text/tailwindcss">
  @layer components {
    .btn {
      @apply rounded border border-line bg-white px-3 py-1.5 font-medium text-ink
             hover:bg-mist focus:outline-none focus:ring-2 focus:ring-pine;
    }
    .btn-primary {
      @apply border-pine bg-pine text-white hover:bg-pine-dark;
    }
    .btn-danger {
      @apply text-brick hover:bg-brick/10;
    }
  }
</style>
