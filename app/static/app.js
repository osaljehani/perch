// Theme toggle — persists the choice and respects the system default first.
(function () {
  const root = document.documentElement;
  const stored = localStorage.getItem("perch-theme");
  if (stored) {
    root.dataset.theme = stored;
  }

  window.toggleTheme = function () {
    const next = root.dataset.theme === "light" ? "dark" : "light";
    root.dataset.theme = next;
    localStorage.setItem("perch-theme", next);
  };
})();
