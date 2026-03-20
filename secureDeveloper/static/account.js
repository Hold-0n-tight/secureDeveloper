document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole, clearSession, routeTo, updateSessionStatus, updateStoredUser } =
    window.boardSkeleton;
  const profileBox = document.querySelector("#profile-card");

  function renderProfile(user) {
    profileBox.classList.remove("empty");
    profileBox.innerHTML = `
      <dl class="profile-grid">
        <div><dt>아이디</dt><dd>${user.username}</dd></div>
        <div><dt>이름</dt><dd>${user.name}</dd></div>
        <div><dt>이메일</dt><dd>${user.email}</dd></div>
        <div><dt>전화번호</dt><dd>${user.phone}</dd></div>
        <div><dt>관리자 여부</dt><dd>${user.is_admin ? "예" : "아니오"}</dd></div>
        <div><dt>잔액</dt><dd>${Number(user.balance || 0).toLocaleString("ko-KR")}</dd></div>
      </dl>
    `;
  }

  async function loadMe() {
    const result = await request("/api/me");
    renderConsole(result);

    if (result.status === 200 && result.payload.user) {
      updateStoredUser(result.payload.user);
      renderProfile(result.payload.user);
      updateSessionStatus();
    }
  }

  document.querySelector("#load-me")?.addEventListener("click", loadMe);

  document.querySelector("#logout-button")?.addEventListener("click", async () => {
    const result = await request("/api/auth/logout", { method: "POST" });
    renderConsole(result);

    if (result.status === 200) {
      clearSession();
      updateSessionStatus();
      routeTo("#/login");
    }
  });

  document.querySelector("#withdraw-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/auth/withdraw", {
      method: "POST",
      body: JSON.stringify({
        password: formData.get("password"),
      }),
    });

    renderConsole(result);
  });

  window.addEventListener("board:route-change", (event) => {
    if (event.detail.view === "account") {
      loadMe();
    }
  });
});
