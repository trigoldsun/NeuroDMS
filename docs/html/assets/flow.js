/* NeuroDMS 手册 · 流程图渲染器
   设计目标：不用 Mermaid，避免"等宽大框 + 交叉箭头"的机械感。
   语义分层：人做的动作（白卡 + 森绿竖标 + 序号）/ 系统自动（灰底）/ 判定（芽绿底）/ 终止（绿=达成，红=失败，黄=待定）。
   序号徽章与下方"步骤表"的编号一一对应，图与表可以互相对照。 */

(function () {
  const NS = 'http://www.w3.org/2000/svg';
  const CW = 216;      // 节点标准宽
  const CGAP = 64;     // 列间距
  const RGAP = 42;     // 行间距
  const PADX = 36;
  const PADY = 18;
  const FS = 13.5;
  const LH = 19;
  const SUBFS = 11.5;
  const SUBLH = 15.5;

  const C = {
    ink: '#0A120E', paper: '#F5F7F2', forest: '#0F5C40', sprout: '#C6EE4B',
    slate: '#66756D', mist: '#A9B5AE', line: '#DDE4DC', wash: '#EDF1EC',
    edge: '#A9B5AE', edgeYes: '#8FAF9B', edgeNo: '#C79B8C',
    bad: '#A6442F', badBg: '#FBEFEC', badLine: '#DCB6A9',
    warn: '#7A5A12', warnBg: '#FDF6E3', warnLine: '#DFC588',
    dec: '#F5F9E6', decLine: '#BCDA6E'
  };

  function charW(ch) {
    if (/[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]/.test(ch)) return FS;
    if (/[A-Z]/.test(ch)) return FS * 0.63;
    if (/[a-z0-9]/.test(ch)) return FS * 0.56;
    if (ch === ' ') return FS * 0.3;
    if (/[·—…]/.test(ch)) return FS * 0.75;
    return FS * 0.5;
  }
  function subCharW(ch) {
    if (/[\u3000-\u303f\u4e00-\u9fff\uff00-\uffef]/.test(ch)) return SUBFS;
    if (/[a-z0-9]/.test(ch)) return SUBFS * 0.56;
    if (/[A-Z]/.test(ch)) return SUBFS * 0.63;
    if (ch === ' ') return SUBFS * 0.3;
    return SUBFS * 0.5;
  }
  function widthOf(s, size, isSub) {
    let w = 0;
    for (const ch of s) w += isSub ? subCharW(ch) : charW(ch);
    return w;
  }
  function tokenize(s) {
    const out = [];
    let buf = '';
    for (const ch of s) {
      if (/[A-Za-z0-9._%+\-/]/.test(ch)) buf += ch;
      else { if (buf) { out.push(buf); buf = ''; } out.push(ch); }
    }
    if (buf) out.push(buf);
    return out;
  }
  function wrap(s, maxW, isSub) {
    const size = isSub ? SUBFS : FS;
    const lines = [];
    let cur = '';
    for (let tk of tokenize(s)) {
      if (tk === ' ' && !cur) continue;
      if (cur && widthOf(cur + tk, size, isSub) > maxW) {
        lines.push(cur.replace(/\s+$/, ''));
        cur = tk === ' ' ? '' : tk;
        // 超长英文串退化为按字符拆
        while (widthOf(cur, size, isSub) > maxW && cur.length > 1) {
          let i = 1;
          while (i < cur.length && widthOf(cur.slice(0, i + 1), size, isSub) <= maxW) i++;
          lines.push(cur.slice(0, i));
          cur = cur.slice(i);
        }
      } else cur += tk;
    }
    if (cur.trim()) lines.push(cur.replace(/\s+$/, ''));
    // 避免行首出现标点
    for (let i = 1; i < lines.length; i++) {
      const m = lines[i].match(/^[，。、；：？！）】》%]+/);
      if (m) { lines[i - 1] += m[0]; lines[i] = lines[i].slice(m[0].length); }
    }
    const out = lines.filter(Boolean);
    // 末行只剩一个字时，从上一行末移一个字下来，避免孤字
    const last = out.length - 1;
    if (last > 0 && out[last].length === 1 && out[last - 1].length > 3 && !/[A-Za-z0-9]/.test(out[last])) {
      const prev = out[last - 1];
      out[last] = prev.slice(-1) + out[last];
      out[last - 1] = prev.slice(0, -1);
    }
    return out;
  }

  function measure(n) {
    if (n.t === 'pill') {
      const w = Math.max(148, Math.min(300, widthOf(n.label, FS) + 58));
      return { w: w, h: 44, lines: [n.label], sublines: [] };
    }
    const W = n.w || CW;
    const maxW = W - 42 - (n.n ? 20 : 0);
    const lines = n.label.split('\n').reduce((a, seg) => a.concat(wrap(seg, maxW, false)), []);
    const sublines = n.sub ? wrap(n.sub, maxW - 2, true) : [];
    const padT = n.t === 'dec' ? 13 : 15;
    const padB = n.t === 'dec' ? 15 : 17;
    const h = padT + lines.length * LH + (sublines.length ? 5 + sublines.length * SUBLH : 0) + padB;
    return { w: W, h: h, lines: lines, sublines: sublines, padT: padT };
  }

  function mk(tag, attrs, text) {
    const e = document.createElementNS(NS, tag);
    if (attrs) for (const k in attrs) if (attrs[k] !== null && attrs[k] !== undefined) e.setAttribute(k, attrs[k]);
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function drawNode(g, n) {
    const grp = mk('g', { class: 'nd' });
    const cx = n.x + n.w / 2;

    if (n.t === 'pill') {
      const fill = n.k === 'ok' ? C.forest : n.k === 'bad' ? C.badBg : n.k === 'warn' ? C.warnBg : '#fff';
      const stroke = n.k === 'ok' ? C.forest : n.k === 'bad' ? C.badLine : n.k === 'warn' ? C.warnLine : '#BCD2C4';
      grp.appendChild(mk('rect', { x: n.x, y: n.y, width: n.w, height: n.h, rx: n.h / 2, fill: fill, stroke: stroke, 'stroke-width': 1.5 }));
      grp.appendChild(mk('text', {
        x: cx, y: n.y + n.h / 2 + 5, 'text-anchor': 'middle', 'font-size': 13.5,
        'font-weight': 600, fill: n.k === 'ok' ? '#F7FAF4' : n.k === 'bad' ? C.bad : n.k === 'warn' ? C.warn : C.ink
      }, n.label));
      g.appendChild(grp);
      return;
    }

    let fill = '#fff', stroke = '#D5DED6', txt = C.ink;
    if (n.t === 'sys') { fill = C.wash; stroke = '#D6DFD7'; txt = '#33403A'; }
    if (n.t === 'dec') { fill = C.dec; stroke = C.decLine; txt = '#22301A'; }
    if (n.t === 'bad') { fill = C.badBg; stroke = C.badLine; txt = C.bad; }
    if (n.t === 'warn') { fill = C.warnBg; stroke = C.warnLine; txt = C.warn; }
    if (n.t === 'adv') { fill = '#fff'; stroke = C.mist; txt = C.slate; }

    const dash = n.t === 'adv' ? '5 4' : null;
    grp.appendChild(mk('rect', {
      x: n.x, y: n.y, width: n.w, height: n.h, rx: n.t === 'dec' ? 15 : 12,
      fill: fill, stroke: stroke, 'stroke-width': 1.2, 'stroke-dasharray': dash
    }));

    // 人做的动作：左侧森绿竖标
    if (n.t === 'act') {
      grp.appendChild(mk('rect', { x: n.x, y: n.y + 11, width: 3.5, height: n.h - 22, rx: 2, fill: C.forest }));
    }
    // 判定：左上小菱形
    if (n.t === 'dec') {
      const dx = n.x + 16, dy = n.y + 15;
      grp.appendChild(mk('path', {
        d: `M${dx},${dy - 4.5} L${dx + 4.5},${dy} L${dx},${dy + 4.5} L${dx - 4.5},${dy} Z`,
        fill: '#7FA31F'
      }));
    }

    // 文字
    const contentH = n.lines.length * LH + (n.sublines.length ? 5 + n.sublines.length * SUBLH : 0);
    let ty = n.y + (n.h - contentH) / 2 + LH * 0.76;
    n.lines.forEach((ln, i) => {
      grp.appendChild(mk('text', {
        x: n.x + 20, y: ty + i * LH, 'font-size': FS,
        'font-weight': n.t === 'dec' ? 600 : 500, fill: txt
      }, ln));
    });
    ty += n.lines.length * LH;
    n.sublines.forEach((ln, i) => {
      grp.appendChild(mk('text', {
        x: n.x + 20, y: ty + 3 + i * SUBLH, 'font-size': SUBFS, fill: n.t === 'bad' ? '#8E5442' : C.slate
      }, ln));
    });

    // 序号徽章（与步骤表编号对应）：放在首行右侧，避免与左侧进线/标签打架
    if (n.n) {
      const contentTop = n.y + (n.h - contentH) / 2;
      const bx = n.x + n.w - 15, by = contentTop + LH * 0.52;
      grp.appendChild(mk('circle', { cx: bx, cy: by, r: 9, fill: C.forest }));
      grp.appendChild(mk('text', {
        x: bx, y: by + 3.6, 'text-anchor': 'middle', 'font-size': 10.5, 'font-weight': 700, fill: '#fff'
      }, String(n.n)));
    }
    g.appendChild(grp);
  }

  function edgeGeom(s, t, edge, busBase, busLane) {
    const scx = s.x + s.w / 2, scy = s.y + s.h / 2;
    const tcx = t.x + t.w / 2, tcy = t.y + t.h / 2;
    const sb = s.y + s.h, et = t.y;

    if (edge.via === 'bus') {
      const bx = busBase + busLane * 15;
      const ey = tcy + (busLane % 2 === 0 ? -5 : 5); // 多条总线错开进入点
      return {
        d: `M${s.x + s.w},${scy} H${bx} V${ey} H${t.x + t.w}`,
        lab: { x: (bx + t.x + t.w) / 2, y: ey - 7, a: 'middle' }
      };
    }
    if (edge.via === 'lane') {
      const right = t.x > s.x;
      const lx = right ? t.x - 30 : t.x + t.w + 30;
      return {
        d: `M${scx},${sb} V${sb + 17} H${lx} V${tcy} H${right ? t.x : t.x + t.w}`,
        lab: { x: (scx + lx) / 2, y: sb + 12, a: 'middle' }
      };
    }
    if (s.c === t.c) {
      return { d: `M${scx},${sb} V${et}`, lab: { x: scx - 9, y: (sb + et) / 2 + 4, a: 'end' } };
    }
    if (s.r === t.r) {
      const right = t.x > s.x;
      return {
        d: `M${right ? s.x + s.w : s.x},${scy} H${right ? t.x : t.x + t.w}`,
        lab: { x: right ? (s.x + s.w + t.x) / 2 : (s.x + t.x + t.w) / 2, y: scy - 9, a: 'middle' }
      };
    }
    const my = (sb + et) / 2;
    const inX = tcx + (t.x > s.x ? -24 : 24); // 侧向来线错开干线
    return { d: `M${scx},${sb} V${my} H${inX} V${et}`, lab: { x: (scx + inX) / 2, y: my - 7, a: 'middle' } };
  }

  /* 自检：连线不得穿过任何方框（端点除外）。只在控制台告警，不影响渲染。 */
  function segmentsOf(d) {
    const segs = [];
    let x = 0, y = 0;
    d.split(/\s+/).forEach(tok => {
      const m = tok.match(/^([MVH])(-?[\d.]+)(?:,(-?[\d.]+))?$/);
      if (!m) return;
      const cmd = m[1];
      if (cmd === 'M') { x = +m[2]; y = +m[3]; return; }
      if (cmd === 'H') { segs.push({ x1: x, y1: y, x2: +m[2], y2: y }); x = +m[2]; return; }
      if (cmd === 'V') { segs.push({ x1: x, y1: y, x2: x, y2: +m[2] }); y = +m[2]; }
    });
    return segs;
  }
  function crosses(seg, n) {
    const p = 3;
    const rx1 = n.x + p, rx2 = n.x + n.w - p, ry1 = n.y + p, ry2 = n.y + n.h - p;
    if (seg.x1 === seg.x2) {
      const lo = Math.min(seg.y1, seg.y2), hi = Math.max(seg.y1, seg.y2);
      return seg.x1 > rx1 && seg.x1 < rx2 && hi > ry1 && lo < ry2;
    }
    const lo = Math.min(seg.x1, seg.x2), hi = Math.max(seg.x1, seg.x2);
    return seg.y1 > ry1 && seg.y1 < ry2 && hi > rx1 && lo < rx2;
  }

  function render(host, spec) {
    const byId = {};
    spec.nodes.forEach(n => { byId[n.id] = n; });

    spec.nodes.forEach(n => {
      const m = measure(n);
      n.w = m.w; n.h = m.h; n.lines = m.lines; n.sublines = m.sublines;
    });

    const rowH = {};
    let maxR = 0, maxC = 0;
    spec.nodes.forEach(n => {
      rowH[n.r] = Math.max(rowH[n.r] || 0, n.h);
      maxR = Math.max(maxR, n.r); maxC = Math.max(maxC, n.c);
    });
    const rowY = {};
    let y = PADY;
    for (let r = 0; r <= maxR; r++) {
      rowY[r] = y;
      y += (rowH[r] || 0) + RGAP;
    }
    spec.nodes.forEach(n => {
      const colX = PADX + n.c * (CW + CGAP);
      n.x = colX + (CW - n.w) / 2;
      n.y = rowY[n.r] + ((rowH[n.r] - n.h) / 2);
    });

    const busCount = spec.edges.filter(e => e.via === 'bus').length;
    const busBase = PADX + maxC * (CW + CGAP) + CW + 26;
    const W = Math.max(660, busBase + Math.max(busCount, 1) * 15 + 26);
    const H = rowY[maxR] + rowH[maxR] + PADY;

    const svg = mk('svg', {
      viewBox: `0 0 ${W} ${H}`, width: W, height: H,
      role: 'img', 'aria-label': spec.title || '', 'font-family': 'inherit'
    });
    svg.appendChild(mk('title', null, spec.title || ''));

    const defs = mk('defs');
    [['mk', C.edge], ['mkY', C.edgeYes], ['mkN', C.edgeNo]].forEach(([id, color]) => {
      const m = mk('marker', {
        id: id + '-' + spec.id, viewBox: '0 0 10 10', refX: 9, refY: 5,
        markerWidth: 6, markerHeight: 6, orient: 'auto-start-reverse'
      });
      m.appendChild(mk('path', { d: 'M0,0 L10,5 L0,10 z', fill: color }));
      defs.appendChild(m);
    });
    svg.appendChild(defs);

    const gEdges = mk('g');
    const gLabels = mk('g');
    let lane = 0;
    spec.edges.forEach(e => {
      const s = byId[e.f], t = byId[e.t];
      if (!s || !t) { console.warn('flow edge missing', spec.id, e); return; }
      const g = edgeGeom(s, t, e, busBase, e.via === 'bus' ? lane++ : 0);
      const col = e.l === '否' ? C.edgeNo : e.l === '是' ? C.edgeYes : C.edge;
      const mid = e.l === '否' ? 'mkN' : e.l === '是' ? 'mkY' : 'mk';
      gEdges.appendChild(mk('path', {
        d: g.d, fill: 'none', stroke: col, 'stroke-width': 1.4,
        'marker-end': `url(#${mid}-${spec.id})`, 'stroke-linejoin': 'round'
      }));
      segmentsOf(g.d).forEach(seg => {
        spec.nodes.forEach(n => {
          if (n.id === s.id || n.id === t.id) return;
          if (crosses(seg, n)) console.warn(`[flow:${spec.id}] ${e.f}→${e.t} 穿过 ${n.id}`);
        });
      });
      if (e.l) {
        const tw = widthOf(e.l, 11) + 12;
        const side = g.lab.a === 'start';
        const end = g.lab.a === 'end';
        const bx = side ? g.lab.x - 3 : end ? g.lab.x - tw + 3 : g.lab.x - tw / 2;
        const tx = side ? g.lab.x + 3 : end ? g.lab.x - 3 : g.lab.x;
        gLabels.appendChild(mk('rect', {
          x: bx, y: g.lab.y - 10.5, width: tw, height: 17, rx: 8.5,
          fill: '#fff', stroke: col === C.edge ? C.line : col, 'stroke-width': 1
        }));
        gLabels.appendChild(mk('text', {
          x: tx, y: g.lab.y + 1.5, 'text-anchor': side ? 'start' : end ? 'end' : 'middle', 'font-size': 11,
          'font-weight': 600, fill: col === C.edge ? C.slate : col
        }, e.l));
      }
    });
    svg.appendChild(gEdges);
    spec.nodes.forEach(n => drawNode(svg, n));
    svg.appendChild(gLabels);

    const wrapEl = document.createElement('div');
    wrapEl.className = 'flow-scroll';
    wrapEl.appendChild(svg);

    host.innerHTML = '';
    const cap = document.createElement('div');
    cap.className = 'flow-cap';
    if (spec.fig) { const f = document.createElement('span'); f.className = 'fig'; f.textContent = spec.fig; cap.appendChild(f); }
    const b = document.createElement('b'); b.textContent = spec.title || ''; cap.appendChild(b);
    if (spec.hint) { const s = document.createElement('span'); s.textContent = spec.hint; cap.appendChild(s); }
    host.appendChild(cap);

    const legend = document.createElement('div');
    legend.className = 'flow-legend';
    legend.innerHTML =
      '<span class="lg-human"><i></i>人 · 需要你操作</span>' +
      '<span class="lg-sys"><i></i>系统 · 自动发生</span>' +
      '<span class="lg-dec"><i></i>判定 · 分岔</span>' +
      '<span class="lg-bad"><i></i>终止 · 失败或被拒</span>';
    host.appendChild(legend);
    host.appendChild(wrapEl);

    if (svg.getAttribute('width') * 1 > 560) {
      const hint = document.createElement('div');
      hint.className = 'flow-hint';
      hint.textContent = '← 左右滑动查看完整流程 →';
      host.appendChild(hint);
    }

    if (spec.foot) {
      const f = document.createElement('div');
      f.className = 'flow-foot';
      f.textContent = spec.foot;
      host.appendChild(f);
    }
  }

  window.FlowChart = { render: render };
})();
