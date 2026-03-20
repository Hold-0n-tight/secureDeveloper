document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole } = window.boardSkeleton;

  document.querySelector("#deposit-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/banking/deposit", {
      method: "POST",
      body: JSON.stringify({
        amount: Number(formData.get("amount")),
      }),
    });

    renderConsole(result);
  });

  document.querySelector("#balance-withdraw-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/banking/withdraw", {
      method: "POST",
      body: JSON.stringify({
        amount: Number(formData.get("amount")),
      }),
    });

    renderConsole(result);
  });

  document.querySelector("#transfer-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/banking/transfer", {
      method: "POST",
      body: JSON.stringify({
        to_username: formData.get("to_username"),
        amount: Number(formData.get("amount")),
      }),
    });

    renderConsole(result);
  });
});
