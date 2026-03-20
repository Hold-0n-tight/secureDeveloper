document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole, getSelectedPostId, clearSelectedPostId, routeTo } = window.boardSkeleton;
  const summaryElement = document.querySelector("#detail-summary");
  const updateForm = document.querySelector("#update-form");

  async function loadDetail() {
    const postId = getSelectedPostId();
    if (!postId) {
      summaryElement.classList.add("empty");
      summaryElement.innerHTML = "<h3>선택된 게시글이 없습니다.</h3><p>먼저 게시글 목록에서 게시글을 선택하세요.</p>";
      return;
    }

    const result = await request(`/api/posts/${postId}`);
    renderConsole(result);
    if (result.status !== 200) return;

    const post = result.payload.post;
    summaryElement.classList.remove("empty");
    summaryElement.innerHTML = `
      <p class="panel-kicker">게시글 #${post.id}</p>
      <h3>${post.title}</h3>
      <p class="meta-line">작성자 ${post.author} | 이메일 ${post.author_email}</p>
      <p class="meta-line">작성일 ${post.created_at} | 수정일 ${post.updated_at}</p>
      <p>${post.content}</p>
    `;

    updateForm.elements.title.value = post.title;
    updateForm.elements.content.value = post.content;
  }

  updateForm?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const postId = getSelectedPostId();
    if (!postId) return;

    const formData = new FormData(event.currentTarget);
    const result = await request(`/api/posts/${postId}`, {
      method: "PUT",
      body: JSON.stringify({
        title: formData.get("title"),
        content: formData.get("content"),
      }),
    });

    renderConsole(result);
    if (result.status === 200 && result.payload.post) {
      summaryElement.classList.remove("empty");
      summaryElement.innerHTML = `
        <p class="panel-kicker">수정 미리보기</p>
        <h3>${result.payload.post.title}</h3>
        <p class="meta-line">작성자 ${result.payload.post.author} | 이메일 ${result.payload.post.author_email}</p>
        <p class="meta-line">수정일 ${result.payload.post.updated_at}</p>
        <p>${result.payload.post.content}</p>
      `;
    }
  });

  document.querySelector("#delete-post")?.addEventListener("click", async () => {
    const postId = getSelectedPostId();
    if (!postId) return;

    const result = await request(`/api/posts/${postId}`, { method: "DELETE" });
    renderConsole(result);
    if (result.status === 200) {
      clearSelectedPostId();
      routeTo("#/posts");
    }
  });

  window.addEventListener("board:route-change", (event) => {
    if (event.detail.view === "detail") {
      loadDetail();
    }
  });
});
