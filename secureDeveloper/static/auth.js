document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole, setSession, routeTo, updateSessionStatus } = window.boardSkeleton;

  document.querySelector("#login-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({
        username: formData.get("username"),
        password: formData.get("password"),
      }),
    });

    renderConsole(result);
    if (result.status === 200) {
      setSession(result.payload);
      updateSessionStatus();
      routeTo("#/posts");
    }
  });

  document.querySelector("#register-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify({
        username: formData.get("username"),
        name: formData.get("name"),
        email: formData.get("email"),
        phone: formData.get("phone"),
        password: formData.get("password"),
      }),
    });

    renderConsole(result);
    if (String(result.status).startsWith("2")) {
      event.currentTarget.reset();
      routeTo("#/login");
    }
  });
});
