/* ==========================================================================
   PhishGuard — front-end behaviour
   --------------------------------------------------------------------------
   Everything here is *progressive enhancement*: without JavaScript the app
   still works (forms POST normally, the server renders every result).
   With JavaScript we add: mobile nav, client-side validation, the scanning
   animation, number count-ups, animated gauges, flash dismissal, the history
   details drawer, the clear-history dialog and a confirm for destructive forms.

   No frameworks, no build step.
   ========================================================================== */
(function () {
  "use strict";

  document.documentElement.classList.add("js");

  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* ------------------------------------------------------------ Header --- */
  function initHeader() {
    const header = $("#siteHeader");
    if (!header) return;
    const onScroll = () => header.classList.toggle("is-scrolled", window.scrollY > 8);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
  }

  /* --------------------------------------------------------- Mobile nav --- */
  function initMobileNav() {
    const toggle = $("#navToggle");
    const links = $("#navLinks");
    if (!toggle || !links) return;

    const close = () => {
      links.classList.remove("is-open");
      toggle.setAttribute("aria-expanded", "false");
    };

    toggle.addEventListener("click", () => {
      const open = links.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", String(open));
    });

    links.addEventListener("click", (e) => {
      if (e.target.closest("a")) close();
    });

    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") close();
    });

    document.addEventListener("click", (e) => {
      if (!links.contains(e.target) && !toggle.contains(e.target)) close();
    });
  }

  /* ----------------------------------------------------- Flash messages --- */
  function initFlash() {
    $$("[data-dismiss-flash]").forEach((btn) => {
      btn.addEventListener("click", () => dismiss(btn.closest(".flash")));
    });
    // Auto-dismiss success messages after a while.
    $$(".flash-success, .flash-warning").forEach((flash) => {
      window.setTimeout(() => dismiss(flash), 6000);
    });
    function dismiss(flash) {
      if (!flash || flash.classList.contains("is-hiding")) return;
      flash.classList.add("is-hiding");
      window.setTimeout(() => flash.remove(), reduceMotion ? 0 : 220);
    }
  }

  /* ---------------------------------------------------- URL validation --- */
  function validateUrl(value) {
    const raw = (value || "").trim();
    if (!raw) return "Enter a URL to analyse.";
    if (raw.length > 2048) return "That URL is longer than 2048 characters.";

    const candidate = raw.includes("://") ? raw : "https://" + raw;
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch (err) {
      return "This does not look like a valid web address. Try https://example.com/login";
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return "Only http:// and https:// addresses can be analysed.";
    }
    const host = parsed.hostname || "";
    if (!host) return "The URL has no hostname.";
    // Browsers accept some odd hosts; require a dot unless it is an IP.
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host.replace(/^\[|\]$/g, ""));
    if (!isIp && !host.includes(".")) {
      return "Enter a full domain, for example.com.";
    }
    return "";
  }

  function initScanner() {
    const form = $("#scanForm");
    if (!form) return;
    const input = $("#url", form);
    const button = $("#analyzeBtn", form);
    const errorEl = $("#url-error", form);
    const loading = $("#scanLoading");

    const showError = (message) => {
      if (!errorEl) return;
      errorEl.textContent = message;
      errorEl.hidden = !message;
      input.setAttribute("aria-invalid", message ? "true" : "false");
    };

    if (input) {
      input.addEventListener("input", () => {
        if (!errorEl || errorEl.hidden) return;
        showError("");
      });
    }

    // Example chips
    $$("[data-fill-url]").forEach((chip) => {
      chip.addEventListener("click", () => {
        input.value = chip.getAttribute("data-fill-url");
        showError("");
        input.focus();
      });
    });

    form.addEventListener("submit", (e) => {
      const message = validateUrl(input.value);
      if (message) {
        e.preventDefault();
        showError(message);
        input.focus();
        return;
      }
      showError("");

      // Show the loading state. The form still submits normally, so the
      // server response is what actually produces the result.
      if (button) {
        button.classList.add("is-loading");
        button.setAttribute("aria-busy", "true");
        button.disabled = true;
      }
      if (loading) loading.hidden = false;
      if (form.querySelector(".form-foot")) form.querySelector(".form-foot").style.opacity = "0.4";
    });
  }

  /* ------------------------------------------- Count-up + gauge reveal --- */
  function animateNumber(el) {
    const target = Number(el.getAttribute("data-count-to"));
    if (!Number.isFinite(target)) return;
    if (reduceMotion) {
      el.textContent = String(target);
      return;
    }
    const duration = 900;
    const start = performance.now();
    const step = (now) => {
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = String(Math.round(target * eased));
      if (progress < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function showGauge(gauge) {
    if (!gauge) return;
    const fill = $(".gauge-fill", gauge);
    if (fill) {
      const offset = fill.getAttribute("data-target-offset");
      // Next frame so the CSS transition runs after the initial paint.
      requestAnimationFrame(() => {
        requestAnimationFrame(() => { fill.style.strokeDashoffset = offset; });
      });
    }
    const score = $(".gauge-score", gauge);
    if (score) animateNumber(score);
    const bar = $(".risk-bar-fill");
    if (bar) {
      const width = bar.getAttribute("data-width");
      requestAnimationFrame(() => {
        requestAnimationFrame(() => { bar.style.width = width + "%"; });
      });
    }
  }

  /* ------------------------------------------------------ Reveal on scroll --- */
  function initReveal() {
    const items = $$("[data-reveal]");
    if (!items.length) return;

    if (!("IntersectionObserver" in window) || reduceMotion) {
      items.forEach((el) => el.classList.add("is-visible"));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            entry.target.classList.add("is-visible");
            observer.unobserve(entry.target);
          }
        });
      },
      { threshold: 0.08, rootMargin: "0px 0px -40px 0px" }
    );
    items.forEach((el) => observer.observe(el));
  }

  /* ------------------------------------------------ History interactions --- */
  function initHistory() {
    // Expandable indicator details
    $$("[data-details-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const row = document.getElementById(btn.getAttribute("aria-controls"));
        if (!row) return;
        const open = row.hasAttribute("hidden");
        row.toggleAttribute("hidden", !open);
        row.classList.toggle("is-open", open);
        btn.setAttribute("aria-expanded", String(open));
      });
    });

    // Destructive forms: confirm() as a no-JS-safe fallback is inline-free here.
    $$("form[data-confirm]").forEach((form) => {
      form.addEventListener("submit", (e) => {
        if (!window.confirm(form.getAttribute("data-confirm"))) e.preventDefault();
      });
    });

    // Clear-history dialog
    const dialog = $("#clearDialog");
    const opener = $("#clearHistoryBtn");
    if (!dialog || !opener) return;

    const supportsDialog = typeof dialog.showModal === "function";

    opener.addEventListener("click", () => {
      if (supportsDialog) {
        dialog.showModal();
        const field = $("#clearConfirm", dialog);
        if (field) window.setTimeout(() => field.focus(), 60);
      } else if (window.confirm("Delete ALL scan history? This cannot be undone.")) {
        $("form.dialog-form", dialog)?.submit();
      }
    });

    $$("[data-dialog-close]", dialog).forEach((btn) => {
      btn.addEventListener("click", () => dialog.close("cancel"));
    });

    // Close when clicking the backdrop
    dialog.addEventListener("click", (e) => {
      if (e.target === dialog) dialog.close("cancel");
    });
  }

  /* ------------------------------------------------------------- Start --- */
  function init() {
    initHeader();
    initMobileNav();
    initFlash();
    initScanner();
    initReveal();
    initHistory();

    // Animate everything visible on load (stats, result gauge, risk bar)
    $$("[data-count-to]").forEach((el) => {
      const inResult = el.closest(".result-header, .result");
      if (!inResult) animateNumber(el);
    });
    showGauge($(".result .gauge"));
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
