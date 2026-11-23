document.addEventListener('DOMContentLoaded', () => {
  const themeButton = document.querySelector('.theme-toggle');
  const savedTheme = localStorage.getItem('myfb-theme');
  const initialTheme = savedTheme === 'dark' || savedTheme === 'light'
    ? savedTheme
    : (typeof window.matchMedia === 'function' && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');

  const applyTheme = (theme) => {
    document.documentElement.dataset.theme = theme;
    if (!themeButton) return;
    const dark = theme === 'dark';
    themeButton.textContent = dark ? 'Light mode' : 'Dark mode';
    themeButton.setAttribute('aria-label', `Switch to ${dark ? 'light' : 'dark'} theme`);
    themeButton.setAttribute('aria-pressed', String(dark));
  };

  applyTheme(initialTheme);
  if (themeButton) {
    themeButton.addEventListener('click', () => {
      const nextTheme = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
      localStorage.setItem('myfb-theme', nextTheme);
      applyTheme(nextTheme);
    });
  }

  document.querySelectorAll('[data-password-strength-for]').forEach((control) => {
    const input = document.getElementById(control.dataset.passwordStrengthFor);
    const meter = control.querySelector('[role="meter"]');
    const label = control.querySelector('[data-strength-label]');
    const adminPolicy = control.dataset.adminPasswordPolicy === 'true';
    const minLength = adminPolicy ? 12 : 6;
    if (!input || !meter || !label) return;

    const updatePasswordStrength = () => {
      const password = input.value;
      const classes = [
        /[a-z]/.test(password),
        /[A-Z]/.test(password),
        /\d/.test(password),
        /[^A-Za-z0-9]/.test(password)
      ].filter(Boolean).length;
      let strength = '';
      let strengthLabel = 'Not entered';
      let score = 0;

      if (password.length > 0) {
        const diverseEnough = adminPolicy ? classes === 4 : classes >= 3;
        if (password.length < minLength || classes <= 1) {
          strength = 'weak';
          strengthLabel = 'Weak';
          score = 1;
        } else if (adminPolicy ? classes < 4 : password.length < 10 || classes === 2) {
          strength = 'fair';
          strengthLabel = 'Fair';
          score = 2;
        } else if (password.length >= 16 && diverseEnough) {
          strength = 'very-strong';
          strengthLabel = 'Very strong';
          score = 4;
        } else if (password.length >= 12 && diverseEnough) {
          strength = 'strong';
          strengthLabel = 'Strong';
          score = 3;
        } else {
          strength = 'fair';
          strengthLabel = 'Fair';
          score = 2;
        }
      }

      control.dataset.strength = strength;
      meter.setAttribute('aria-valuenow', String(score));
      meter.setAttribute('aria-valuetext', strengthLabel);
      label.textContent = strengthLabel;
    };

    input.addEventListener('input', updatePasswordStrength);
    updatePasswordStrength();
  });

  const toggleButton = document.querySelector('.nav-toggle');
  const nav = document.querySelector('.main-nav');

  if (toggleButton && nav) {
    toggleButton.addEventListener('click', () => {
      const isOpen = nav.classList.toggle('open');
      toggleButton.setAttribute('aria-expanded', String(isOpen));
      toggleButton.setAttribute('aria-label', isOpen ? 'Close navigation menu' : 'Open navigation menu');
    });

    nav.querySelectorAll('a').forEach((link) => link.addEventListener('click', () => {
      nav.classList.remove('open');
      toggleButton.setAttribute('aria-expanded', 'false');
      toggleButton.setAttribute('aria-label', 'Open navigation menu');
    }));
  }

  document.querySelectorAll('[data-chat-thread]').forEach((thread) => {
    thread.scrollTop = thread.scrollHeight;
  });

  document.querySelectorAll('.nav-link').forEach((link) => {
    if (link.pathname === window.location.pathname) {
      link.classList.add('is-active');
      link.setAttribute('aria-current', 'page');
    }
  });

  document.querySelectorAll('form').forEach((form) => {
    form.addEventListener('submit', () => {
      const submit = form.querySelector('button[type="submit"]');
      if (!submit || submit.dataset.submitted === 'true') return;
      submit.dataset.submitted = 'true';
      submit.setAttribute('aria-busy', 'true');
      submit.classList.add('is-loading');
      window.setTimeout(() => {
        submit.dataset.submitted = 'false';
        submit.removeAttribute('aria-busy');
        submit.classList.remove('is-loading');
      }, 4000);
    });
  });

  const revealItems = document.querySelectorAll('.info-card, .timeline-item, .highlight-card, .stat-card, .glass-panel');
  if ('IntersectionObserver' in window && !window.matchMedia('(prefers-reduced-motion: reduce)').matches) {
    revealItems.forEach((item) => item.classList.add('reveal-ready'));
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add('revealed');
        observer.unobserve(entry.target);
      });
    }, { threshold: 0.12 });
    revealItems.forEach((item) => observer.observe(item));
  }
});
