// Index page: sample loading and clear. No inline scripts (CSP script-src 'self').
(function () {
  "use strict";

  const textarea = document.getElementById("raw-header");
  const clearBtn = document.getElementById("clear-btn");
  const sampleBtns = document.querySelectorAll(".btn-sample");

  sampleBtns.forEach((btn) => {
    btn.addEventListener("click", async () => {
      const name = btn.getAttribute("data-sample");
      try {
        const res = await fetch(`/samples/${encodeURIComponent(name)}`);
        if (!res.ok) return;
        textarea.value = await res.text();
      } catch (err) {
        // Network failure loading a local sample is unusual; fail quietly rather
        // than showing a raw stack trace to the analyst.
      }
    });
  });

  if (clearBtn) {
    clearBtn.addEventListener("click", () => {
      textarea.value = "";
      const upload = document.getElementById("eml-upload");
      if (upload) upload.value = "";
    });
  }
})();
