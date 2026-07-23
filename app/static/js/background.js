// Ambient background: a faint network grid with occasional traveling pulses.
//
// Deliberately restrained — this app is read for actual analyst work (dense tables,
// hop timelines, raw header dumps), so the background must never compete with text
// contrast. Dots and lines only, no glow/blur, opacity capped low. Respects
// prefers-reduced-motion by rendering the static grid with no pulses at all.
(function () {
  "use strict";

  var canvas = document.getElementById("bg-canvas");
  if (!canvas || !canvas.getContext) return;

  var ctx = canvas.getContext("2d");
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var SPACING = 46;
  var DOT_RADIUS = 1.15;
  var LINE_ALPHA = 0.07;
  var DOT_ALPHA = 0.12;
  var PULSE_ALPHA = 0.6;
  var PULSE_SPEED = 0.0055; // fraction of a segment per frame
  var MAX_PULSES = 6;
  var PULSE_SPAWN_CHANCE = 0.014; // per frame, per idle slot
  var EDGE_KEEP_PROB = 0.5; // fraction of candidate edges drawn

  var width = 0;
  var height = 0;
  var cols = 0;
  var rows = 0;
  var edges = []; // {x1,y1,x2,y2,w}  w = falloff weight, 0..1
  var pulses = []; // {edge, t}
  var dpr = Math.min(window.devicePixelRatio || 1, 2);
  var rafId = null;
  var focusX = 0;
  var focusY = 0;
  var falloffRadius = 1;

  function resize() {
    width = window.innerWidth;
    height = window.innerHeight;
    canvas.width = width * dpr;
    canvas.height = height * dpr;
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    // Anchor the densest, brightest part of the mesh near the masthead/intro
    // rather than spreading uniform noise across the whole viewport — gives the
    // pattern a single deliberate focal point instead of reading as random static.
    focusX = width * 0.72;
    focusY = height * 0.12;
    falloffRadius = Math.max(width, height) * 0.75;
    buildGrid();
  }

  function buildGrid() {
    cols = Math.ceil(width / SPACING) + 1;
    rows = Math.ceil(height / SPACING) + 1;
    edges = [];
    // A sparse, deliberately irregular subset of grid connections — a full grid
    // reads as a spreadsheet; skipping most links reads as a network diagram.
    // Edges close to the focal point are kept more often and drawn brighter, so
    // the mesh visibly radiates from one place instead of looking torn/uniform.
    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        var x = c * SPACING;
        var y = r * SPACING;
        var w = falloffWeight(x, y);
        if (c < cols - 1 && pseudoRandom(r, c, 1) > EDGE_KEEP_PROB - w * 0.25) {
          edges.push({ x1: x, y1: y, x2: x + SPACING, y2: y, w: w });
        }
        if (r < rows - 1 && pseudoRandom(r, c, 2) > EDGE_KEEP_PROB - w * 0.25) {
          edges.push({ x1: x, y1: y, x2: x, y2: y + SPACING, w: w });
        }
      }
    }
    pulses = [];
  }

  // 1 near the focal point, fading smoothly to a low floor at the far edges of
  // the viewport so the mesh never disappears entirely, just recedes.
  function falloffWeight(x, y) {
    var dx = x - focusX;
    var dy = y - focusY;
    var dist = Math.sqrt(dx * dx + dy * dy);
    var t = Math.min(1, dist / falloffRadius);
    return 0.25 + 0.75 * (1 - t * t);
  }

  // Deterministic per-cell pseudo-randomness so the grid doesn't reshuffle on resize
  // jitter (e.g. mobile browser chrome show/hide).
  function pseudoRandom(r, c, salt) {
    var n = Math.sin(r * 12.9898 + c * 78.233 + salt * 37.719) * 43758.5453;
    return n - Math.floor(n);
  }

  function draw() {
    ctx.clearRect(0, 0, width, height);

    // Edges are drawn individually (rather than one batched path) so each can
    // carry its own focal-falloff alpha — the cost is negligible at this edge
    // count and it's what makes the mesh read as radiating from one point.
    ctx.lineWidth = 1;
    for (var i = 0; i < edges.length; i++) {
      var e = edges[i];
      ctx.strokeStyle = "rgba(125, 180, 232, " + (LINE_ALPHA * e.w).toFixed(3) + ")";
      ctx.beginPath();
      ctx.moveTo(e.x1, e.y1);
      ctx.lineTo(e.x2, e.y2);
      ctx.stroke();
    }

    for (var r = 0; r < rows; r++) {
      for (var c = 0; c < cols; c++) {
        var x = c * SPACING;
        var y = r * SPACING;
        var w = falloffWeight(x, y);
        ctx.fillStyle = "rgba(125, 180, 232, " + (DOT_ALPHA * w).toFixed(3) + ")";
        ctx.beginPath();
        ctx.arc(x, y, DOT_RADIUS, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    if (!reduceMotion) {
      drawPulses();
    }
  }

  function drawPulses() {
    if (pulses.length < MAX_PULSES && edges.length && Math.random() < PULSE_SPAWN_CHANCE) {
      pulses.push({ edge: edges[(Math.random() * edges.length) | 0], t: 0 });
    }

    for (var i = pulses.length - 1; i >= 0; i--) {
      var p = pulses[i];
      p.t += PULSE_SPEED;
      if (p.t >= 1) {
        pulses.splice(i, 1);
        continue;
      }
      var x = p.edge.x1 + (p.edge.x2 - p.edge.x1) * p.t;
      var y = p.edge.y1 + (p.edge.y2 - p.edge.y1) * p.t;
      var alpha = PULSE_ALPHA * p.edge.w * Math.sin(Math.PI * p.t); // fades in, then out

      // Short trailing tail behind the head, so it reads as travelling motion
      // rather than a dot that just appears and vanishes.
      var bx = p.edge.x1 + (p.edge.x2 - p.edge.x1) * Math.max(0, p.t - 0.05);
      var by = p.edge.y1 + (p.edge.y2 - p.edge.y1) * Math.max(0, p.t - 0.05);
      ctx.strokeStyle = "rgba(180, 215, 245, " + (alpha * 0.5).toFixed(3) + ")";
      ctx.lineWidth = 1.4;
      ctx.beginPath();
      ctx.moveTo(bx, by);
      ctx.lineTo(x, y);
      ctx.stroke();

      ctx.fillStyle = "rgba(200, 226, 250, " + alpha.toFixed(3) + ")";
      ctx.beginPath();
      ctx.arc(x, y, 2, 0, Math.PI * 2);
      ctx.fill();
    }
  }

  function loop() {
    draw();
    rafId = requestAnimationFrame(loop);
  }

  // A visibility check avoids burning cycles in a background tab.
  document.addEventListener("visibilitychange", function () {
    if (document.hidden && rafId) {
      cancelAnimationFrame(rafId);
      rafId = null;
    } else if (!document.hidden && !rafId) {
      loop();
    }
  });

  window.addEventListener("resize", resize);
  resize();

  if (reduceMotion) {
    draw(); // one static frame, no animation loop at all
  } else {
    loop();
  }
})();
