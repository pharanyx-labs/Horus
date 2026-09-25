/* Horus website behaviour. Progressive enhancement only: every page reads and
   navigates completely without it. Nothing here makes a network request; the
   search index is a script file from this site (assets/search-index.js), which
   also works when the pages are opened straight from a checkout. */
(function () {
  "use strict";
  var root = document.documentElement;

  /* ---- Links from the old single page -------------------------------------
     The site used to be one page, so links such as /#limits exist in the wild.
     On the home page, send those to where the section lives now. */
  var MOVED = {
    what: "why.html#what", capability: "why.html#capability",
    anatomy: "architecture.html#anatomy", architecture: "architecture.html#architecture",
    boot: "boot.html#boot", run: "run.html#run", status: "status.html#status",
    next: "status.html#next", method: "testing.html#method", limits: "limitations.html#limits"
  };
  if (document.body.classList.contains("page-index")) {
    var h = location.hash.replace("#", "");
    if (MOVED[h]) { location.replace(MOVED[h]); return; }
  }

  /* ---- The home page's token figure plays its reveal once, when first seen ---- */
  var token = document.querySelector(".token");
  if (token && "IntersectionObserver" in window &&
      !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    var seen = new IntersectionObserver(function (entries) {
      if (entries.some(function (en) { return en.isIntersecting; })) {
        token.classList.add("is-playing");
        seen.disconnect();
      }
    }, { threshold: 0.35 });
    seen.observe(token);
  }

  /* ---- Theme: automatic, light, dark ---------------------------------------- */
  var themeBtn = document.querySelector("[data-theme-toggle]");
  var ORDER = ["auto", "light", "dark"];
  function currentTheme() { return root.getAttribute("data-theme") || "auto"; }
  function labelTheme() {
    if (!themeBtn) return;
    var t = currentTheme();
    var text = "Colour theme: " + (t === "auto" ? "automatic, following your system" : t);
    themeBtn.setAttribute("aria-label", text);
    themeBtn.setAttribute("title", text);
  }
  if (themeBtn) {
    labelTheme();
    themeBtn.addEventListener("click", function () {
      var next = ORDER[(ORDER.indexOf(currentTheme()) + 1) % ORDER.length];
      if (next === "auto") root.removeAttribute("data-theme");
      else root.setAttribute("data-theme", next);
      try {
        if (next === "auto") localStorage.removeItem("horus-theme");
        else localStorage.setItem("horus-theme", next);
      } catch (e) { /* storage unavailable: the choice lasts for this page only */ }
      labelTheme();
    });
  }

  /* ---- The menu closes when a link in it is followed, or on Escape ------------ */
  var menu = document.querySelector(".menu");
  if (menu) {
    menu.addEventListener("click", function (e) { if (e.target.closest("a")) menu.open = false; });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape" && menu.open) { menu.open = false; menu.querySelector("summary").focus(); }
    });
    document.addEventListener("click", function (e) { if (menu.open && !menu.contains(e.target)) menu.open = false; });
  }

  /* ---- Contents rail: mark the section being read --------------------------- */
  var tocLinks = Array.prototype.slice.call(document.querySelectorAll(".toc a[href^='#']"));
  if (tocLinks.length && "IntersectionObserver" in window) {
    var byId = {};
    tocLinks.forEach(function (a) { byId[decodeURIComponent(a.hash.slice(1))] = a; });
    var targets = Object.keys(byId).map(function (id) { return document.getElementById(id); }).filter(Boolean);
    var visible = new Set();
    var setCurrent = function () {
      var first = targets.find(function (t) { return visible.has(t); });
      if (!first) return;
      tocLinks.forEach(function (a) { a.classList.remove("is-current"); a.removeAttribute("aria-current"); });
      var link = byId[first.id];
      link.classList.add("is-current");
      link.setAttribute("aria-current", "location");
    };
    var io = new IntersectionObserver(function (entries) {
      entries.forEach(function (en) { if (en.isIntersecting) visible.add(en.target); else visible.delete(en.target); });
      setCurrent();
    }, { rootMargin: "-80px 0px -65% 0px" });
    targets.forEach(function (t) { io.observe(t); });
  }

  /* ---- Search over every heading on every page -------------------------------- */
  var dialog = document.getElementById("search");
  var input = document.getElementById("search-q");
  var list = document.getElementById("search-results");
  var status = document.getElementById("search-status");
  /* Screen readers hear a count, not the whole list on every keystroke. The
     active result is marked with a class: aria-selected is not valid on a link,
     and Tab still walks the results as ordinary links. */
  function announce(n, q) {
    if (!status) return;
    status.textContent = !q ? "" : n === 0 ? "No results" : n + (n === 1 ? " result" : " results");
  }
  var INDEX = window.HORUS_SEARCH || [];
  var selected = 0;

  function norm(s) { return s.toLowerCase().normalize("NFKD").replace(/[̀-ͯ]/g, ""); }
  function score(item, words) {
    var t = norm(item.t), p = norm(item.p), s = 0;
    for (var i = 0; i < words.length; i++) {
      var w = words[i];
      if (t.indexOf(w) === 0) s += 6;
      else if (t.indexOf(" " + w) >= 0) s += 4;
      else if (t.indexOf(w) >= 0) s += 2;
      else if (p.indexOf(w) >= 0) s += 1;
      else return 0;
    }
    return s + (item.k === 1 ? 2 : item.k === 2 ? 1 : 0);
  }
  function render() {
    var q = norm(input.value.trim());
    var words = q.split(/\s+/).filter(Boolean);
    var items = !words.length
      ? INDEX.filter(function (x) { return x.k === 1; })
      : INDEX.map(function (x) { return [score(x, words), x]; })
             .filter(function (p) { return p[0] > 0; })
             .sort(function (a, b) { return b[0] - a[0]; })
             .slice(0, 40).map(function (p) { return p[1]; });
    list.innerHTML = "";
    if (!items.length) {
      var li = document.createElement("li");
      li.className = "search__empty";
      li.textContent = "Nothing on this site matches that. Try a shorter word, such as boot, token or test.";
      list.appendChild(li);
      announce(0, q);
      return;
    }
    items.forEach(function (x, i) {
      var li = document.createElement("li");
      var a = document.createElement("a");
      a.href = x.u;
      a.textContent = x.t;
      if (x.k !== 1) { var sp = document.createElement("span"); sp.textContent = x.p; a.appendChild(sp); }
      if (i === 0) a.classList.add("is-active");
      li.appendChild(a);
      list.appendChild(li);
    });
    selected = 0;
    announce(items.length, q);
  }
  function move(d) {
    var links = list.querySelectorAll("a");
    if (!links.length) return;
    links[selected].classList.remove("is-active");
    selected = (selected + d + links.length) % links.length;
    links[selected].classList.add("is-active");
    links[selected].scrollIntoView({ block: "nearest" });
  }
  function openSearch() {
    if (!dialog || typeof dialog.showModal !== "function") return;
    if (!dialog.open) dialog.showModal();
    input.value = "";
    render();
    input.focus();
  }
  if (dialog && input && list) {
    document.querySelectorAll("[data-search-open]").forEach(function (b) { b.addEventListener("click", openSearch); });
    document.addEventListener("keydown", function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
      if ((e.key === "k" && (e.ctrlKey || e.metaKey)) || (e.key === "/" && !typing && !dialog.open)) {
        e.preventDefault();
        openSearch();
      }
    });
    input.addEventListener("input", render);
    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") {
        var a = list.querySelectorAll("a")[selected];
        if (a) { e.preventDefault(); dialog.close(); location.href = a.href; }
      }
    });
    list.addEventListener("click", function (e) { if (e.target.closest("a")) dialog.close(); });
    dialog.addEventListener("click", function (e) { if (e.target === dialog) dialog.close(); });
  }

  /* ---- The capability walkthrough (Why Horus) ---------------------------------
     The SVG's visible layers are chosen purely by the wrapper's data-step in CSS,
     so this moves that attribute, swaps the caption and keeps aria-current honest.
     Without JavaScript the page shows step 1 and still reads correctly. */
  var walk = document.getElementById("walk");
  if (walk) {
    var buttons = walk.querySelectorAll("[data-go]");
    var notes = walk.querySelectorAll("[data-note]");
    var show = function (step) {
      walk.setAttribute("data-step", step);
      buttons.forEach(function (b) { b.setAttribute("aria-current", b.dataset.go === step ? "true" : "false"); });
      notes.forEach(function (n) { n.hidden = n.dataset.note !== step; });
    };
    buttons.forEach(function (b) { b.addEventListener("click", function () { show(b.dataset.go); }); });
  }

  /* ---- Status: filter by state ---------------------------------------------------- */
  var table = document.querySelector(".table--status");
  if (table) {
    var rows = Array.prototype.slice.call(table.tBodies[0].rows);
    var stateOf = function (r) {
      var p = r.querySelector(".pill");
      return p ? p.textContent.trim().toLowerCase() : "other";
    };
    var counts = {};
    rows.forEach(function (r) { var s = stateOf(r); counts[s] = (counts[s] || 0) + 1; });
    var bar = document.createElement("div");
    bar.className = "filter";
    bar.setAttribute("role", "group");
    bar.setAttribute("aria-label", "Show subsystems by state");
    var make = function (label, key, n) {
      var b = document.createElement("button");
      b.type = "button";
      b.dataset.key = key;
      b.setAttribute("aria-pressed", key === "all" ? "true" : "false");
      b.textContent = label;
      var sp = document.createElement("span");
      sp.textContent = n;
      b.appendChild(sp);
      bar.appendChild(b);
    };
    make("All", "all", rows.length);
    ["working", "partial", "not yet"].forEach(function (k) {
      if (counts[k]) make(k.charAt(0).toUpperCase() + k.slice(1), k, counts[k]);
    });
    /* What the filter left showing, said once, for screen readers and sighted
       readers alike: a filtered table with no word about it looks complete. */
    var shown = document.createElement("p");
    shown.className = "filter__count";
    shown.setAttribute("role", "status");
    shown.textContent = "Showing all " + rows.length + " subsystems.";
    bar.addEventListener("click", function (e) {
      var b = e.target.closest("button");
      if (!b) return;
      bar.querySelectorAll("button").forEach(function (x) { x.setAttribute("aria-pressed", x === b ? "true" : "false"); });
      var n = 0;
      rows.forEach(function (r) {
        r.hidden = !(b.dataset.key === "all" || stateOf(r) === b.dataset.key);
        if (!r.hidden) n++;
      });
      shown.textContent = b.dataset.key === "all"
        ? "Showing all " + rows.length + " subsystems."
        : "Showing " + n + " of " + rows.length + " subsystems: " + b.dataset.key + ".";
    });
    var wrap = table.closest(".tablewrap") || table;
    wrap.parentNode.insertBefore(bar, wrap);
    wrap.parentNode.insertBefore(shown, wrap);
  }
})();
