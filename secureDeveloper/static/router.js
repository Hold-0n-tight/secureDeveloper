document.addEventListener("DOMContentLoaded", () => {
  const links = document.querySelectorAll("[data-route-link]");
  const views = document.querySelectorAll("[data-view]");

  const hashToViewMap = {
    "#/login": "login",
    "#/register": "register",
    "#/posts": "posts",
    "#/compose": "compose",
    "#/detail": "detail",
    "#/account": "account",
    "#/banking": "banking",
  };

  function renderRoute() {
    const currentHash = window.location.hash || "#/login";
    const activeView = hashToViewMap[currentHash] || "login";

    views.forEach((view) => {
      view.classList.toggle("is-active", view.dataset.view === activeView);
    });

    links.forEach((link) => {
      link.classList.toggle("is-active", link.getAttribute("href") === currentHash);
    });

    window.dispatchEvent(
      new CustomEvent("board:route-change", {
        detail: { hash: currentHash, view: activeView },
      }),
    );
  }

  window.addEventListener("hashchange", renderRoute);
  if (!window.location.hash) {
    window.location.hash = "#/login";
  }
  renderRoute();
});
