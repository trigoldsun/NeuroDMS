/* NeuroDMS 手册 · 交互脚本
   1) 侧栏目录自动生成 + 滚动高亮
   2) 站内搜索（标题权重高于正文）
   3) 标题锚点与打印
   4) 角色能力矩阵的"点列高亮"
   5) 渲染所有 .flow[data-flow] 流程图 */

(function () {
  const main = document.querySelector('main');
  if (!main) return;

  // 取标题纯文本：去掉序号与锚点符号
  function titleOf(h) {
    const c = h.cloneNode(true);
    c.querySelectorAll('.anchor, .num').forEach(x => x.remove());
    return (h.dataset.nav || c.textContent).replace(/\s+/g, ' ').replace(/#+$/, '').trim();
  }

  /* ---------- 标题锚点 ---------- */
  const heads = Array.from(main.querySelectorAll('h2[id], h3[id]'));
  heads.forEach(h => {
    const a = document.createElement('a');
    a.className = 'anchor';
    a.href = '#' + h.id;
    a.textContent = '#';
    a.setAttribute('aria-label', '本节链接');
    a.addEventListener('click', (e) => {
      e.preventDefault();
      history.replaceState(null, '', '#' + h.id);
      h.scrollIntoView({ behavior: 'smooth', block: 'start' });
      if (navigator.clipboard) navigator.clipboard.writeText(location.href).catch(() => {});
    });
    h.appendChild(a);
  });
  const st = document.createElement('style');
  st.textContent = 'h2 .anchor,h3 .anchor{opacity:0;margin-left:8px;font-size:.7em;color:#A9B5AE;text-decoration:none;transition:opacity .15s}h2:hover .anchor,h3:hover .anchor{opacity:1}';
  document.head.appendChild(st);

  /* ---------- 侧栏目录 ---------- */
  const toc = document.querySelector('.toc');
  let tocLinks = [];
  if (toc) {
    const nav = document.createElement('div');
    heads.forEach(h => {
      const label = titleOf(h);
      if (!label) return;
      if (h.tagName === 'H3' && !h.dataset.nav) return;
      const a = document.createElement('a');
      a.href = '#' + h.id;
      a.textContent = label.replace(/^#\s*/, '');
      if (h.tagName === 'H3') a.className = 'sub';
      a.addEventListener('click', () => {
        document.body.classList.remove('toc-open');
        if (toc) toc.classList.remove('open');
      });
      nav.appendChild(a);
    });
    toc.appendChild(nav);
    tocLinks = Array.from(nav.querySelectorAll('a'));
  }

  /* ---------- 滚动高亮 ---------- */
  let ticking = false;
  function onScroll() {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(() => {
      ticking = false;
      const top = window.scrollY + 120;
      let cur = null;
      heads.forEach(h => { if (h.offsetTop <= top) cur = h.id; });
      tocLinks.forEach(a => a.classList.toggle('active', a.getAttribute('href') === '#' + cur));
      const btn = document.querySelector('.totop');
      if (btn) btn.classList.toggle('on', window.scrollY > 600);
    });
  }
  window.addEventListener('scroll', onScroll, { passive: true });
  window.addEventListener('resize', onScroll);
  onScroll();

  /* 移动端目录按钮 */
  const tocBtn = document.querySelector('.toc-btn');
  if (tocBtn && toc) {
    tocBtn.addEventListener('click', () => {
      toc.classList.toggle('open');
      document.body.classList.toggle('toc-open', toc.classList.contains('open'));
    });
  }

  /* ---------- 站内搜索 ---------- */
  const input = document.querySelector('.search input');
  const resBox = document.querySelector('.search-res');
  let index = [];

  function buildIndex() {
    const nodes = Array.from(main.querySelectorAll('h2[id], h3[id]'));
    nodes.forEach(h => {
      let txt = '';
      let el = h.nextElementSibling;
      while (el && !/^H[23]$/.test(el.tagName)) {
        txt += ' ' + (el.innerText || el.textContent || '');
        el = el.nextElementSibling;
      }
      index.push({
        id: h.id,
        title: titleOf(h),
        text: txt.replace(/\s+/g, ' ').trim()
      });
    });
  }
  buildIndex();

  function search(q) {
    const toks = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!toks.length) return [];
    const out = [];
    index.forEach(it => {
      const t = it.title.toLowerCase(), b = it.text.toLowerCase();
      let score = 0, hit = true;
      toks.forEach(k => {
        const inT = t.includes(k), inB = b.includes(k);
        if (!inT && !inB) hit = false;
        if (inT) score += 6;
        if (inB) score += 1;
      });
      if (!hit) return;
      out.push({ it: it, score: score });
    });
    out.sort((a, b) => b.score - a.score);
    return out.slice(0, 8);
  }

  function snippet(text, q) {
    const k = q.split(/\s+/).filter(Boolean)[0] || '';
    const i = k ? text.toLowerCase().indexOf(k.toLowerCase()) : -1;
    if (i < 0) return text.slice(0, 46);
    return text.slice(Math.max(0, i - 14), Math.max(0, i - 14) + 52);
  }

  if (input && resBox) {
    let sel = -1;
    const hide = () => { resBox.classList.remove('on'); sel = -1; };
    input.addEventListener('input', () => {
      const q = input.value.trim();
      if (!q) { hide(); return; }
      const rs = search(q);
      resBox.innerHTML = '';
      if (!rs.length) {
        resBox.innerHTML = '<div class="empty">没有匹配的章节。试试更短的词，比如"审批""密级""续传"。</div>';
      } else {
        rs.forEach((r, i) => {
          const a = document.createElement('a');
          a.href = '#' + r.it.id;
          a.innerHTML = '';
          a.appendChild(document.createTextNode(r.it.title));
          const s = document.createElement('small');
          s.textContent = snippet(r.it.text, q);
          a.appendChild(s);
          a.addEventListener('click', hide);
          resBox.appendChild(a);
        });
      }
      resBox.classList.add('on');
      sel = -1;
    });
    input.addEventListener('keydown', (e) => {
      const items = Array.from(resBox.querySelectorAll('a'));
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        if (!items.length) return;
        sel = e.key === 'ArrowDown' ? (sel + 1) % items.length : (sel - 1 + items.length) % items.length;
        items.forEach((a, i) => a.classList.toggle('sel', i === sel));
        items[sel].scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Enter') {
        const go = sel >= 0 ? items[sel] : items[0];
        if (go) { location.hash = go.getAttribute('href'); go.click(); hide(); input.blur(); }
      } else if (e.key === 'Escape') { hide(); input.blur(); }
    });
    document.addEventListener('click', (e) => { if (!e.target.closest('.search')) hide(); });
    document.addEventListener('keydown', (e) => {
      if ((e.key === '/' || (e.key === 'k' && (e.metaKey || e.ctrlKey))) && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault(); input.focus();
      }
    });
  }

  /* ---------- 回到顶部 / 打印 ---------- */
  const toTop = document.querySelector('.totop');
  if (toTop) toTop.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));
  document.querySelectorAll('[data-print]').forEach(b => b.addEventListener('click', () => window.print()));

  /* ---------- 能力矩阵：点列高亮 ---------- */
  const matrix = document.querySelector('.matrix');
  if (matrix) {
    const ths = Array.from(matrix.querySelectorAll('thead th[data-role]'));
    ths.forEach(th => {
      th.addEventListener('click', () => {
        const on = th.classList.contains('on');
        ths.forEach(t => t.classList.remove('on'));
        matrix.querySelectorAll('td[data-col]').forEach(td => td.classList.remove('col-on'));
        if (!on) {
          th.classList.add('on');
          matrix.querySelectorAll('td[data-col="' + th.dataset.role + '"]').forEach(td => td.classList.add('col-on'));
        }
      });
    });
  }

  /* ---------- 流程图 ---------- */
  document.querySelectorAll('.flow[data-flow]').forEach(el => {
    const spec = window.FLOWS && window.FLOWS[el.dataset.flow];
    if (!spec) { console.warn('missing flow', el.dataset.flow); return; }
    window.FlowChart.render(el, spec);
  });
})();
