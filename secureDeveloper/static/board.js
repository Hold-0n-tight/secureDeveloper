document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole, setSelectedPostId, getSelectedPostId, routeTo } = window.boardSkeleton;
  const listElement = document.querySelector("#post-list");
  const previewElement = document.querySelector("#post-preview");

  function renderPreview(post) {
    if (!previewElement) return;

    previewElement.classList.remove("empty");
    previewElement.innerHTML = `
      <p class="panel-kicker">선택된 게시글</p>
      <h3>${post.title}</h3>
      <p class="meta-line">작성자 ${post.author} | 이메일 ${post.author_email}</p>
      <p class="meta-line">수정일 ${post.updated_at}</p>
      <p>${post.content}</p>
    `;
  }

  async function loadPosts() {
    const result = await request("/api/posts");
    renderConsole(result);

    if (result.status !== 200 || !listElement) return;

    const posts = result.payload.posts || [];
    if (posts.length === 0) {
      listElement.innerHTML = "<p class='empty-copy'>현재 표시할 게시글이 없습니다.</p>";
      previewElement.classList.add("empty");
      previewElement.innerHTML = "<h3>선택된 게시글이 없습니다.</h3><p>이 영역에는 선택한 게시글 미리보기가 표시됩니다.</p>";
      return;
    }

    listElement.innerHTML = posts
      .map(
        (post) => `
          <button class="post-item" type="button" data-post-id="${post.id}">
            <strong>${post.title}</strong>
            <span>${post.author} | ${post.author_email}</span>
          </button>
        `,
      )
      .join("");

    const selectedId = getSelectedPostId();
    const selectedPost = posts.find((post) => String(post.id) === String(selectedId)) || posts[0];
    setSelectedPostId(selectedPost.id);
    renderPreview(selectedPost);
  }

  async function loadPostDetail(postId) {
    const result = await request(`/api/posts/${postId}`);
    renderConsole(result);

    if (result.status === 200) {
      setSelectedPostId(postId);
      renderPreview(result.payload.post);
    }
  }

  document.querySelector("#load-posts")?.addEventListener("click", loadPosts);

  listElement?.addEventListener("click", (event) => {
    const button = event.target.closest("[data-post-id]");
    if (!button) return;
    loadPostDetail(button.dataset.postId);
  });

  document.querySelector("#open-detail")?.addEventListener("click", () => {
    routeTo("#/detail");
  });

  window.addEventListener("board:route-change", (event) => {
    if (event.detail.view === "posts") {
      loadPosts();
    }
  });
});
