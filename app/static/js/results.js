// Results page: refang toggle and (later) motion. No inline scripts.
(function () {
  "use strict";

  const toggle = document.getElementById("refang-toggle");
  if (toggle) {
    toggle.addEventListener("change", () => {
      document.querySelectorAll(".defanged").forEach((el) => {
        el.textContent = toggle.checked
          ? el.getAttribute("data-real")
          : el.getAttribute("data-real-defanged") || el.textContent;
      });
    });
    // Cache the defanged text once so re-toggling doesn't need a second data attribute
    // computed server-side.
    document.querySelectorAll(".defanged").forEach((el) => {
      if (!el.getAttribute("data-real-defanged")) {
        el.setAttribute("data-real-defanged", el.textContent);
      }
    });
  }
})();
