document.addEventListener("DOMContentLoaded", () => {
  const { request, renderConsole, setSelectedPostId, routeTo } = window.boardSkeleton;

  document.querySelector("#compose-form")?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const formData = new FormData(event.currentTarget);

    const result = await request("/api/posts", {
      method: "POST",
      body: JSON.stringify({
        title: formData.get("title"),
        content: formData.get("content"),
      }),
    });

    renderConsole(result);
    if (result.status === 201 && result.payload.post) {
      setSelectedPostId(result.payload.post.id);
      event.currentTarget.reset();
      routeTo("#/detail");
    }
  });
});
