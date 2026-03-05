const root = document.getElementById('messages');
const form = document.getElementById('message-form');
const csrf = root?.dataset.csrf;

function esc(str) {
  const div = document.createElement('div');
  div.textContent = str;
  return div.innerHTML;
}

async function postForm(url, data) {
  const fd = new URLSearchParams(data);
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8',
      'X-CSRF-Token': csrf,
    },
    body: fd,
  });
  return res.json();
}

function render(messages) {
  root.innerHTML = '';
  messages.forEach((m) => {
    const el = document.createElement('article');
    el.className = `message ${m.mine ? 'mine' : ''}`;
    const reactions = m.reaction_users.join(', ');

    el.innerHTML = `
      <div class="meta">${esc(m.author)} • ${esc(m.created_at.replace('T', ' '))}</div>
      <div>${esc(m.content)}</div>
      <div class="message-controls">
        <button class="plain-btn reply-btn" data-id="${m.id}">Ответить</button>
        <button class="plain-btn react-msg" data-id="${m.id}" title="${esc(reactions)}">👍 ${m.reaction_count}</button>
      </div>
      <div class="reply-form-wrap" id="reply-form-${m.id}" hidden>
        <form class="reply-form" data-id="${m.id}">
          <input name="content" placeholder="Ваш ответ" required>
          <button class="btn btn-secondary" type="submit">Отправить</button>
        </form>
      </div>
      <div class="replies">
      ${m.replies.map((r) => `
        <div class="reply">
          <div class="meta">${esc(r.author)} • ${esc(r.created_at.replace('T', ' '))}</div>
          <div>${esc(r.content)}</div>
          <button class="plain-btn react-reply" data-id="${r.id}" title="${esc(r.reaction_users.join(', '))}">👍 ${r.reaction_count}</button>
        </div>
      `).join('')}
      </div>
    `;
    root.appendChild(el);
  });
  root.scrollTop = root.scrollHeight;
}

async function loadMessages() {
  const res = await fetch('/api/messages');
  const data = await res.json();
  render(data);
}

form?.addEventListener('submit', async (e) => {
  e.preventDefault();
  const content = form.querySelector('#content').value.trim();
  if (!content) return;
  await postForm('/api/messages', { content });
  form.reset();
  await loadMessages();
});

root?.addEventListener('click', async (e) => {
  const replyToggle = e.target.closest('.reply-btn');
  if (replyToggle) {
    const id = replyToggle.dataset.id;
    const target = document.getElementById(`reply-form-${id}`);
    target.hidden = !target.hidden;
    return;
  }

  const reactMsg = e.target.closest('.react-msg');
  if (reactMsg) {
    await postForm(`/api/messages/${reactMsg.dataset.id}/react`, {});
    await loadMessages();
    return;
  }

  const reactReply = e.target.closest('.react-reply');
  if (reactReply) {
    await postForm(`/api/replies/${reactReply.dataset.id}/react`, {});
    await loadMessages();
  }
});

root?.addEventListener('submit', async (e) => {
  const f = e.target.closest('.reply-form');
  if (!f) return;
  e.preventDefault();
  const id = f.dataset.id;
  const content = f.querySelector('input[name="content"]').value.trim();
  if (!content) return;
  await postForm(`/api/messages/${id}/reply`, { content });
  await loadMessages();
});

loadMessages();
setInterval(loadMessages, 6000);
