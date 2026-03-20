window.boardSkeleton = (function () {
  const SESSION_KEY = "boardSkeleton.session";
  const SELECTED_POST_KEY = "boardSkeleton.selectedPostId";

  function getSession() {
    const raw = window.localStorage.getItem(SESSION_KEY);
    return raw ? JSON.parse(raw) : null;
  }

  function setSession(session) {
    window.localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  }

  function updateStoredUser(user) {
    const session = getSession();
    if (!session) return;
    session.user = user;
    setSession(session);
  }

  function clearSession() {
    window.localStorage.removeItem(SESSION_KEY);
    clearSelectedPostId();
  }

  function getSelectedPostId() {
    return window.localStorage.getItem(SELECTED_POST_KEY);
  }

  function setSelectedPostId(postId) {
    window.localStorage.setItem(SELECTED_POST_KEY, String(postId));
  }

  function clearSelectedPostId() {
    window.localStorage.removeItem(SELECTED_POST_KEY);
  }

  function routeTo(hash) {
    window.location.hash = hash;
  }

  async function request(path, options = {}) {
    const headers = { ...(options.headers || {}) };
    if (options.body) {
      headers["Content-Type"] = "application/json";
    }

    const session = getSession();
    if (session?.token) {
      headers.Authorization = session.token;
    }

    const response = await fetch(path, {
      ...options,
      headers,
      credentials: "include",
    });

    let payload;
    try {
      payload = await response.json();
    } catch (error) {
      payload = { message: "JSON 응답이 없습니다.", error: error.message };
    }

    return { status: response.status, payload };
  }

  function renderConsole(data) {
    const output = document.querySelector("#console-output");
    if (!output) return;
    output.textContent = JSON.stringify(data, null, 2);
  }

  function updateSessionStatus() {
    const box = document.querySelector("#session-status");
    if (!box) return;

    const session = getSession();
    if (!session?.user) {
      box.textContent = "아직 Authorization 토큰이 없습니다.";
      return;
    }

    const user = session.user;
    const balance = Number(user.balance || 0).toLocaleString("ko-KR");
    const scope = user.is_admin ? "관리자" : "일반 사용자";
    box.textContent = `${user.name || user.username} 로그인됨, 권한 ${scope}, Authorization 헤더 준비됨, 잔액 ${balance}`;
  }

  return {
    getSession,
    setSession,
    updateStoredUser,
    clearSession,
    getSelectedPostId,
    setSelectedPostId,
    clearSelectedPostId,
    routeTo,
    request,
    renderConsole,
    updateSessionStatus,
  };
})();

document.addEventListener("DOMContentLoaded", () => {
  window.boardSkeleton.updateSessionStatus();
});
