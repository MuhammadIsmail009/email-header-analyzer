// GSAP motion layer. Loaded on every page (base.html) so the same conventions apply
// everywhere; each block below no-ops harmlessly if its target elements aren't on
// the current page.
//
// prefers-reduced-motion is read once at load (this is a server-rendered app with
// full page reloads, not an SPA, so there's no live media-query change to react to
// mid-session). Deliberately NOT using gsap.matchMedia()'s object-conditions form
// here — in the vendored gsap.min.js build this app ships, mm.add({name: query}, cb)
// never invokes its callback at all (confirmed: the single-query-string form
// mm.add(query, cb) fires fine, only the multi-condition object form is broken),
// which silently no-op'd every animation on the page. Reading matchMedia directly
// has no such failure mode.
(function () {
  "use strict";

  if (typeof gsap === "undefined") {
    // Vendored script failed to load for some reason — reveal hidden content
    // immediately rather than leaving it invisible.
    document.querySelectorAll(".gsap-hidden").forEach(function (el) {
      el.classList.remove("gsap-hidden");
      el.style.opacity = "";
    });
    return;
  }

  if (typeof ScrollTrigger !== "undefined") {
    gsap.registerPlugin(ScrollTrigger);
  }

  // GSAP's ticker is requestAnimationFrame-driven, which browsers freeze in a
  // backgrounded tab. A tween that starts while the tab is still active (e.g.
  // right as a page navigation lands) can get caught mid-flight the instant
  // focus moves away — most visibly the verdict-score count-up, which would
  // otherwise sit frozen at 0 until (if ever) the tab is looked at again.
  // visibilitychange is a plain DOM event, not gated on rAF, so it still fires
  // for a hidden tab: use it to force every in-flight tween to its end state
  // immediately rather than leaving anything stuck mid-animation.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden) {
      gsap.globalTimeline.getChildren(true, true, false).forEach(function (tween) {
        tween.progress(1);
      });
    }
  });

  // Treat "page loaded into an already-backgrounded tab" the same as reduced
  // motion: jump straight to the end state. Content that starts hidden for a
  // GSAP .from() entrance has no other way to become visible if the tab never
  // gets a paintable rAF tick to run that entrance on.
  var reduceMotion =
    window.matchMedia("(prefers-reduced-motion: reduce)").matches || document.hidden;

  setupPageLoadReveal(reduceMotion);
  setupVerdictEntrance(reduceMotion);
  setupScrollReveals(reduceMotion);
  setupFindingsToggle(reduceMotion);
  setupButtonFeedback(reduceMotion);

  // -------------------------------------------------------------------------
  // Page load: header + first content block settle in. Kept short and single-
  // layer — this fires on every navigation (this is a server-rendered app with
  // full page loads, not an SPA), so it must never feel like it's in the way of
  // getting to the next click.
  // -------------------------------------------------------------------------
  function setupPageLoadReveal(reduceMotion) {
    var topbar = document.querySelector(".topbar");
    var brandMark = document.querySelector(".brand-mark");
    var heading = document.querySelector(".intro h1");
    var intro = document.querySelector(".intro, .verdict-card");

    if (reduceMotion) {
      document.querySelectorAll(".gsap-hidden").forEach(function (el) {
        el.classList.remove("gsap-hidden");
      });
      gsap.set([topbar, intro].filter(Boolean), { clearProps: "all" });
      return;
    }

    var tl = gsap.timeline({ defaults: { ease: "power3.out" } });
    if (topbar) {
      tl.from(topbar, { y: -20, autoAlpha: 0, duration: 0.55 }, 0);
    }
    if (brandMark) {
      // The one deliberately punchy beat on the page: a quick overshoot pop on
      // the mark, timed with its CSS boot-pulse ring (see style.css), so the
      // instant the app is visible it reads as "just switched on."
      tl.from(brandMark, { scale: 0, rotate: -35, duration: 0.55, ease: "back.out(2.2)" }, 0.05);
    }
    if (heading) {
      tl.from(
        heading,
        { scale: 0.92, y: 22, autoAlpha: 0, filter: "blur(10px)", duration: 0.7, ease: "power3.out" },
        0.15
      );
      if (intro && intro !== heading) {
        tl.from(
          gsap.utils.toArray(intro.querySelectorAll(":scope > *:not(h1)")),
          { y: 20, autoAlpha: 0, filter: "blur(6px)", duration: 0.55, stagger: 0.08, ease: "power3.out" },
          0.35
        );
      }
    } else if (intro) {
      tl.from(intro, { y: 20, autoAlpha: 0, filter: "blur(6px)", duration: 0.6 }, 0.15);
    }

    // Panels below the fold that aren't scroll-triggered individually (form,
    // analyze form) get one gentle staggered rise.
    var panels = gsap.utils.toArray(".analyze-form, .config-status");
    if (panels.length) {
      tl.from(panels, { y: 18, autoAlpha: 0, duration: 0.5, stagger: 0.1, ease: "power3.out" }, 0.4);
    }

    document.querySelectorAll(".gsap-hidden").forEach(function (el) {
      el.classList.remove("gsap-hidden");
    });
  }

  // -------------------------------------------------------------------------
  // Verdict card: the payoff of clicking Analyze. Scales/fades in, then the
  // score counts up from 0 — this is the one place a slightly more deliberate
  // entrance earns its keep, since it's the answer the analyst submitted for.
  // -------------------------------------------------------------------------
  function setupVerdictEntrance(reduceMotion) {
    var card = document.querySelector('[data-animate="verdict"]');
    if (!card) return;

    var scoreEl = card.querySelector(".verdict-score");
    var target = scoreEl ? parseInt(scoreEl.getAttribute("data-count-to") || "0", 10) : 0;

    // If the tab is backgrounded right as this page loads, GSAP's rAF-driven
    // ticker won't tick at all, so a count-up tween can sit at its start value
    // indefinitely. Skip straight to the final value in that case instead of
    // gambling on the tab regaining focus.
    if (reduceMotion || document.hidden) {
      if (scoreEl) scoreEl.textContent = String(target);
      gsap.set(card, { clearProps: "all" });
      return;
    }

    gsap.from(card, { y: 26, scale: 0.97, autoAlpha: 0, filter: "blur(8px)", duration: 0.65, ease: "power3.out" });

    if (scoreEl) {
      var counter = { value: 0 };
      gsap.to(counter, {
        value: target,
        duration: Math.min(1.1, 0.35 + target / 90),
        ease: "power1.out",
        delay: 0.15,
        onUpdate: function () {
          scoreEl.textContent = String(Math.round(counter.value));
        },
        // Hard safety net: guarantee the displayed score matches data-count-to
        // exactly on completion, even if intermediate frames were dropped.
        onComplete: function () {
          scoreEl.textContent = String(target);
        },
      });
    }
  }

  // -------------------------------------------------------------------------
  // Scroll-triggered reveals: hop timeline entries draw in one at a time as the
  // route panel scrolls into view; the trust-boundary marker wipes in after its
  // neighbouring hops have landed. Findings stagger in by their existing DOM
  // order (already severity-sorted server-side).
  // -------------------------------------------------------------------------
  function setupScrollReveals(reduceMotion) {
    if (typeof ScrollTrigger === "undefined") return;

    var timelinePanel = document.querySelector('[data-animate="timeline"]');
    if (timelinePanel) {
      var hops = gsap.utils.toArray(timelinePanel.querySelectorAll(".hop"));
      var boundary = timelinePanel.querySelector(".boundary-marker");

      if (reduceMotion) {
        gsap.set(hops, { clearProps: "all" });
        if (boundary) gsap.set(boundary, { clearProps: "all" });
      } else if (hops.length) {
        gsap.from(hops, {
          x: -28,
          autoAlpha: 0,
          filter: "blur(4px)",
          duration: 0.55,
          ease: "power3.out",
          stagger: 0.14,
          scrollTrigger: {
            trigger: timelinePanel,
            start: "top 80%",
            toggleActions: "play none none none",
          },
        });
        if (boundary) {
          gsap.from(boundary, {
            scaleX: 0,
            transformOrigin: "left center",
            duration: 0.6,
            ease: "power2.inOut",
            delay: hops.length * 0.14,
            scrollTrigger: {
              trigger: timelinePanel,
              start: "top 80%",
              toggleActions: "play none none none",
            },
          });
        }
      }
    }

    var findingsPanel = document.querySelector('[data-animate="findings"]');
    if (findingsPanel) {
      var findings = gsap.utils.toArray(findingsPanel.querySelectorAll(".finding"));
      if (reduceMotion) {
        gsap.set(findings, { clearProps: "all" });
      } else if (findings.length) {
        gsap.from(findings, {
          y: 24,
          autoAlpha: 0,
          filter: "blur(4px)",
          duration: 0.5,
          ease: "power3.out",
          stagger: 0.08,
          scrollTrigger: {
            trigger: findingsPanel,
            start: "top 85%",
            toggleActions: "play none none none",
          },
        });
      }
    }

    // Every other panel: a light fade/rise as it enters view. Batched so N
    // panels cost one ScrollTrigger group, not N individual ones.
    var otherPanels = gsap.utils.toArray(".panel").filter(function (el) {
      return !el.closest('[data-animate="timeline"]') && !el.closest('[data-animate="findings"]');
    });
    if (otherPanels.length) {
      if (reduceMotion) {
        gsap.set(otherPanels, { clearProps: "all" });
      } else {
        ScrollTrigger.batch(otherPanels, {
          start: "top 88%",
          onEnter: function (batch) {
            gsap.from(batch, {
              y: 24,
              autoAlpha: 0,
              filter: "blur(5px)",
              duration: 0.55,
              stagger: 0.1,
              ease: "power3.out",
            });
          },
          once: true,
        });
      }
    }
  }

  // -------------------------------------------------------------------------
  // Findings <details>/<summary>: replace the browser's instant show/hide with
  // a smooth height animation. Progressive enhancement — without JS the native
  // <details> element still works exactly as expected, just without the tween.
  // -------------------------------------------------------------------------
  function setupFindingsToggle(reduceMotion) {
    var findings = document.querySelectorAll(".finding");
    findings.forEach(function (details) {
      var summary = details.querySelector("summary");
      var body = details.querySelector(".finding-body");
      if (!summary || !body) return;

      summary.addEventListener("click", function (event) {
        event.preventDefault();

        if (reduceMotion) {
          details.open = !details.open;
          return;
        }

        if (!details.open) {
          details.open = true;
          gsap.from(body, { height: 0, autoAlpha: 0, duration: 0.28, ease: "power1.out" });
        } else {
          gsap.to(body, {
            height: 0,
            autoAlpha: 0,
            duration: 0.22,
            ease: "power1.in",
            onComplete: function () {
              details.open = false;
              gsap.set(body, { clearProps: "height" });
            },
          });
        }
      });
    });
  }

  // -------------------------------------------------------------------------
  // Click feedback on buttons: a quick, cheap press-and-settle. gsap.quickTo
  // reuses one tween per element instead of creating a new one per click.
  // -------------------------------------------------------------------------
  function setupButtonFeedback(reduceMotion) {
    if (reduceMotion) return;

    document.querySelectorAll(".btn").forEach(function (btn) {
      var pressTo = gsap.quickTo(btn, "scale", { duration: 0.15, ease: "power2.out" });
      btn.style.transformOrigin = "center";
      btn.addEventListener("pointerdown", function () {
        pressTo(0.96);
      });
      ["pointerup", "pointerleave", "pointercancel"].forEach(function (evt) {
        btn.addEventListener(evt, function () {
          pressTo(1);
        });
      });
    });
  }
})();
