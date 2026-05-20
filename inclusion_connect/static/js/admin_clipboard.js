document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("a[data-copy-to-clipboard]").forEach(function (link) {
    link.addEventListener("click", function (e) {
      e.preventDefault();
      const original = link.textContent;
      navigator.clipboard.writeText(window.location.origin + link.getAttribute("href")).then(function () {
        link.textContent = "Lien copié !";
        setTimeout(function () {
          link.textContent = original;
        }, 2000);
      });
    });
  });
});
