(() => {
  const root = document.documentElement;
  const saved = localStorage.getItem('canarynorth-theme');
  root.dataset.theme = saved === 'light' || saved === 'dark'
    ? saved
    : (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

  const attachToggle = () => {
    const toggle = document.querySelector('#theme-toggle');
    if (!toggle) return;

    const update = () => {
      const dark = root.dataset.theme === 'dark';
      toggle.setAttribute('aria-pressed', String(dark));
      toggle.querySelector('.theme-label').textContent = dark ? 'Light mode' : 'Dark mode';
      toggle.querySelector('.theme-icon').textContent = dark ? '☼' : '◐';
    };

    update();
    toggle.addEventListener('click', () => {
      root.dataset.theme = root.dataset.theme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('canarynorth-theme', root.dataset.theme);
      update();
    });
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', attachToggle, { once: true });
  } else {
    attachToggle();
  }
})();
