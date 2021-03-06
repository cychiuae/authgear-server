import Turbolinks from "turbolinks";
import { init } from "./core";
// FIXME(css): Build CSS files one by one with another tool
// webpack bundles all CSS files into one bundle.

init();

window.api.onLoad(() => {
  document.body.classList.add("js");
});

// Handle form submission

function setNetworkError() {
  const field = document.querySelector(".errors");
  if (field) {
    field.textContent = field.getAttribute("data-network-error");
  }
}

function setServerError() {
  const field = document.querySelector(".errors");
  if (field) {
    field.textContent = field.getAttribute("data-server-error");
  }
}

window.api.onLoad(() => {
  let isSubmitting = false;
  function submitForm(e: Event) {
    e.preventDefault();
    e.stopPropagation();
    if (isSubmitting) {
      return;
    }
    isSubmitting = true;

    const form = e.currentTarget as HTMLFormElement;
    const formData = new FormData(form);

    const params = new URLSearchParams();
    formData.forEach((value, name) => {
      params.set(name, value as string);
    });
    // FormData does not include any submit button's data:
    // include them manually, since we have at most one submit button per form.
    const submitButtons = form.querySelectorAll('button[type="submit"]');
    for (let i = 0; i < submitButtons.length; i++) {
      const button = submitButtons[i] as HTMLButtonElement;
      params.set(button.name, button.value);
    }
    if (form.id) {
      const el = document.querySelector(
        `button[type="submit"][form="${form.id}"]`
      );
      if (el) {
        const button = el as HTMLButtonElement;
        params.set(button.name, button.value);
      }
    }

    fetch(form.action, {
      method: form.method,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
        "X-Authgear-XHR": "true"
      },
      credentials: "same-origin",
      body: params
    })
      .then(resp => {
        if (resp.status < 200 || resp.status >= 300) {
          isSubmitting = false;
          setServerError();
          return;
        }
        return resp.json().then(({ redirect_uri, action }) => {
          isSubmitting = false;

          Turbolinks.clearCache();
          switch (action) {
            case "redirect":
              // Perform full redirect.
              window.location = redirect_uri;
              break;

            case "replace":
            case "advance":
              Turbolinks.visit(redirect_uri, { action });
              break;
          }
        });
      })
      .catch(() => {
        isSubmitting = false;
        setNetworkError();
      });
  }

  const elems = document.querySelectorAll("form");
  const forms: HTMLFormElement[] = [];
  for (let i = 0; i < elems.length; i++) {
    if (elems[i].querySelector('[data-form-xhr="false"]')) {
      continue;
    }
    forms.push(elems[i] as HTMLFormElement);
  }
  for (const form of forms) {
    form.addEventListener("submit", submitForm);
  }

  return () => {
    for (const form of forms) {
      form.removeEventListener("submit", submitForm);
    }
  };
});

function refreshPage() {
  let url = window.location.pathname;
  if (window.location.search !== "") {
    url += "?" + window.location.search;
  }
  if (window.location.hash !== "") {
    url += "#" + window.location.hash;
  }
  Turbolinks.visit(url, { action: "replace" });
}

// Handle password visibility toggle.
window.api.onLoad(() => {
  const wrappers = document.querySelectorAll(".password-input-wrapper");
  const disposers: Array<() => void> = [];
  for (let i = 0; i < wrappers.length; i++) {
    const wrapper = wrappers[i];
    const input = wrapper.querySelector(".input") as HTMLInputElement;
    const showPasswordButton = wrapper.querySelector(".show-password-button");
    const hidePasswordButton = wrapper.querySelector(".hide-password-button");
    if (!input || !showPasswordButton || !hidePasswordButton) {
      return;
    }

    if (wrapper.classList.contains("show-password")) {
      input.type = "text";
    } else {
      input.type = "password";
    }

    const togglePasswordVisibility = (e: Event) => {
      e.preventDefault();
      e.stopPropagation();
      wrapper.classList.toggle("show-password");
      if (wrapper.classList.contains("show-password")) {
        input.type = "text";
      } else {
        input.type = "password";
      }
    };

    showPasswordButton.addEventListener("click", togglePasswordVisibility);
    hidePasswordButton.addEventListener("click", togglePasswordVisibility);
    disposers.push(() => {
      showPasswordButton.removeEventListener("click", togglePasswordVisibility);
      hidePasswordButton.removeEventListener("click", togglePasswordVisibility);
    });
  }

  return () => {
    for (const disposer of disposers) {
      disposer();
    }
  };
});

// Handle resend button.
window.api.onLoad(() => {
  const el = document.querySelector("#resend-button") as HTMLButtonElement;
  if (el == null) {
    return;
  }

  const scheduledAt = new Date();
  const cooldown = Number(el.getAttribute("data-cooldown")) * 1000;
  const label = el.getAttribute("data-label");
  const labelUnit = el.getAttribute("data-label-unit")!;
  let animHandle: number | null = null;

  function tick() {
    const now = new Date();
    const timeElapsed = now.getTime() - scheduledAt.getTime();

    let displaySeconds = 0;
    if (timeElapsed <= cooldown) {
      displaySeconds = Math.round((cooldown - timeElapsed) / 1000);
    }

    if (displaySeconds === 0) {
      el.disabled = false;
      el.textContent = label;
      animHandle = null;
    } else {
      el.disabled = true;
      el.textContent = labelUnit.replace("%d", String(displaySeconds));
      animHandle = requestAnimationFrame(tick);
    }
  }

  animHandle = requestAnimationFrame(tick);

  return () => {
    if (animHandle != null) {
      cancelAnimationFrame(animHandle);
    }
  };
});

// Handle auto form submission
window.api.onLoad(() => {
  const e = document.querySelector('[data-auto-submit="true"]');
  if (e instanceof HTMLElement) {
    e.removeAttribute("data-auto-submit");
    e.click();
  }
});

// Handle click link switch label and href
window.api.onLoad(() => {
  const groups = document.querySelectorAll(".switch-link-group");
  const disposers: Array<() => void> = [];
  for (let i = 0; i < groups.length; i++) {
    const wrapper = groups[i];
    const clickToSwitchLink = wrapper.querySelector(
      ".click-to-switch"
    ) as HTMLAnchorElement;
    const switchLinks = (e: Event) => {
      wrapper.classList.add("switched");
    };
    clickToSwitchLink.addEventListener("click", switchLinks);
    disposers.push(() => {
      clickToSwitchLink.removeEventListener("click", switchLinks);
    });
  }

  return () => {
    for (const disposer of disposers) {
      disposer();
    }
  };
});

// Handle back button click.

function handleBack(pathname: string): boolean {
  const pathComponents = pathname.split("/").filter(c => c !== "");
  if (pathComponents.length > 1 && pathComponents[0] === "settings") {
    const newPathname = "/" + pathComponents.slice(0, pathComponents.length - 1).join("/");
    Turbolinks.visit(newPathname, { action: "replace" });
    return true;
  }
  return false;
}

let pathnameBeforeOnPopState = window.location.pathname;
function onPopState(_e: Event) {
  // When this event handler runs, location reflects the latest change.
  // So window.location is useless to us here.
  handleBack(pathnameBeforeOnPopState);
}
window.api.onLoad(() => {
  pathnameBeforeOnPopState = window.location.pathname;
  window.addEventListener("popstate", onPopState);
  return () => {
    window.removeEventListener("popstate", onPopState);
  };
});
function onClickBackButton(e: Event) {
  e.preventDefault();
  e.stopPropagation();
  const handled = handleBack(window.location.pathname);
  if (handled) {
    return;
  }
  window.history.back();
}
window.api.onLoad(() => {
  const elems = document.querySelectorAll(".back-btn");
  for (let i = 0; i < elems.length; i++) {
    elems[i].addEventListener("click", onClickBackButton);
  }
  return () => {
    for (let i = 0; i < elems.length; i++) {
      elems[i].removeEventListener("click", onClickBackButton);
    }
  };
});

// Websocket runtime
window.api.onLoad(() => {
  const scheme = window.location.protocol === "https:" ? "wss:" : "ws:";
  const host = window.location.host;
  var meta: HTMLMetaElement | null = document.querySelector(
    'meta[name="x-authgear-page-loaded-at"]'
  );
  let sessionUpdatedAfter = "";
  if (meta != null) {
    sessionUpdatedAfter = meta.content || "";
  }

  let ws: WebSocket | null = null;

  function dispose() {
    if (ws != null) {
      ws.onclose = function () {};
      ws.close();
    }
    ws = null;
  }

  function refreshIfNeeded() {
    const ele = document.querySelector('[data-is-refresh-link="true"]');
    if (ele) {
      // if there is refresh link in the page, don't refresh automatically
      return;
    }
    refreshPage();
  }

  function connect() {
    const url =
      `${scheme}//${host}/ws` +
      (sessionUpdatedAfter
        ? `?session_updated_after=${sessionUpdatedAfter}`
        : "");

    ws = new WebSocket(url);

    ws.onopen = function (e) {
      console.log("ws onopen", e);
      // after connected, we don't need to check session updated again when
      // reconnect
      // clear the checking parameter
      sessionUpdatedAfter = "";
    };

    ws.onclose = function(e) {
      console.log("ws onclose", e);
      // Close code 1000 means we do not need to reconnect.
      if (e.code === 1000) {
        return;
      }

      dispose();
      connect();
    };

    ws.onerror = function(e) {
      console.error("ws onerror", e);
    };

    ws.onmessage = function (e) {
      console.log("ws onmessage", e);
      const message = JSON.parse(e.data);
      switch (message.kind) {
        case "refresh":
          refreshIfNeeded();
      }
    };
  }

  connect();
  return dispose;
});
