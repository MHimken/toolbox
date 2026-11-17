(function () {
  'use strict';

  const data = JSON.parse(document.getElementById('explorerData').textContent);
  const logic = window.ExplorerLogic;
  const groups = Array.isArray(data.groups) ? data.groups : [];
  const groupById = new Map(groups.map((group) => [String(group.id).toLowerCase(), group]));
  const options = data.options || { maxNameLength: 30, abbreviationStyle: 'Middle', initialDepth: 2, autoExpandLimit: 10 };
  const autoExpandLimit = Number(options.autoExpandLimit ?? 10);
  // Card width follows the abbreviation length; unabbreviated names (0) are cut by CSS at 40 characters.
  document.documentElement.style.setProperty('--name-chars', String(Number(options.maxNameLength) > 0 ? Number(options.maxNameLength) : 40));
  const searchShell = document.getElementById('searchShell');
  const selectedView = document.getElementById('selectedView');
  const search = document.getElementById('groupSearch');
  const suggestions = document.getElementById('groupSuggestions');
  const searchStatus = document.getElementById('searchStatus');
  let activeIndex = -1;
  let selectedGroup = null;
  let zoom = 1;
  const renderedNodeCount = { parents: 0, children: 0 };
  const nodeBudget = { parents: 400, children: 400 };

  function element(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function groupName(group) {
    return String(group && group.name || '(unnamed group)');
  }

  function getGroup(id) {
    return groupById.get(String(id).toLowerCase()) || null;
  }

  function dangerText(group) {
    const danger = group.danger || {};
    const lines = [];
    if (danger.self) {
      const reasons = Array.isArray(danger.reason) ? danger.reason.join('; ') : String(danger.reason || 'Configured as dangerous');
      lines.push({ text: `Dangerous group: ${reasons}`, own: true });
    }
    if (Number(danger.nestedCount) > 0) lines.push({ text: `Contains ${danger.nestedCount} dangerous group(s)`, own: false });
    if (Number(danger.ancestorCount) > 0) lines.push({ text: `Used by ${danger.ancestorCount} dangerous group(s)`, own: false });
    return lines;
  }

  function addWarnings(parent, group, compact) {
    const items = dangerText(group);
    if (compact && items.length) {
      // Tree cards show one badge (the most severe) so labels stay narrow; every reason stays in the tooltip.
      const own = items.some((item) => item.own);
      const warning = element('span', `warning-symbol${own ? '' : ' outlined'}`, own ? 'Dangerous' : 'Warning');
      warning.title = items.map((item) => item.text).join('. ');
      parent.appendChild(warning);
      return;
    }
    for (const item of items) {
      const warning = element('span', `warning-symbol${item.own ? '' : ' outlined'}`, item.own ? 'Dangerous' : 'Warning');
      warning.setAttribute('aria-label', item.text);
      warning.title = item.text;
      parent.appendChild(warning);
    }
  }

  function addCountTable(parent, counts) {
    const table = element('table', 'count-table');
    const caption = element('caption', '', 'Membership counts');
    table.appendChild(caption);
    const head = document.createElement('thead');
    const headingRow = document.createElement('tr');
    for (const label of ['Type', 'Direct', 'Including nested']) headingRow.appendChild(element('th', '', label));
    head.appendChild(headingRow);
    table.appendChild(head);
    const body = document.createElement('tbody');
    for (const kind of ['users', 'devices', 'groups']) {
      const row = document.createElement('tr');
      row.appendChild(element('th', '', kind[0].toUpperCase() + kind.slice(1)));
      row.appendChild(element('td', '', formatCount(counts && counts.direct && counts.direct[kind])));
      row.appendChild(element('td', '', formatCount(counts && counts.nested && counts.nested[kind])));
      body.appendChild(row);
    }
    table.appendChild(body);
    parent.appendChild(table);
  }

  function formatCount(value) {
    return value === null || value === undefined ? 'Unavailable' : Number(value).toLocaleString();
  }

  function createMetaPanel(group) {
    const panel = element('div', 'meta-panel');
    const details = document.createElement('dl');
    const rows = [
      ['Full name', groupName(group)],
      ['Group id', group.id],
      ['Type', group.type],
      ['Membership', group.membership],
      ['Description', group.description],
      ['Created', group.created],
      ['Role-assignable', group.roleAssignable ? 'Yes' : 'No'],
      ['On-premises sync', group.onPremSynced ? 'Yes' : 'No']
    ];
    for (const [label, value] of rows) {
      if (value === undefined || value === null || value === '') continue;
      details.appendChild(element('dt', '', label));
      details.appendChild(element('dd', '', value));
    }
    panel.appendChild(details);
    addCountTable(panel, group.counts || {});
    for (const warning of dangerText(group)) panel.appendChild(element('p', 'warning-line', warning.text));
    if (Array.isArray(group.flags) && group.flags.length) {
      panel.appendChild(element('p', 'warning-line', `Data quality: ${group.flags.join(', ')}`));
    }
    const useCenter = element('button', 'use-center', 'Use as center');
    useCenter.type = 'button';
    useCenter.addEventListener('click', () => selectGroup(group));
    panel.appendChild(useCenter);
    return panel;
  }

  const relationCollator = new Intl.Collator();
  function getRelations(group, direction) {
    const relationIds = Array.isArray(group[direction]) ? group[direction] : [];
    return relationIds.map(getGroup).filter(Boolean)
      .sort((left, right) => relationCollator.compare(groupName(left), groupName(right)));
  }

  function createMoreButton(container, direction, remaining, resume) {
    const item = document.createElement('li');
    const button = element('button', 'more-toggle', `Show ${remaining} more related group(s)`);
    button.type = 'button';
    button.addEventListener('click', () => {
      nodeBudget[direction] += 100;
      item.remove();
      resume();
    });
    item.appendChild(button);
    container.appendChild(item);
    return item;
  }

  function createBranchNode(group, direction, level, path) {
    if (renderedNodeCount[direction] >= nodeBudget[direction]) return null;
    renderedNodeCount[direction] += 1;
    const item = document.createElement('li');
    const card = element('article', 'node');
    card.style.setProperty('--depth', String(Math.min(level, 6)));
    const nextPath = new Set(path);
    const key = String(group.id).toLowerCase();
    if (nextPath.has(key)) {
      card.appendChild(element('p', 'empty-message', `Cycle: ${groupName(group)}`));
      item.appendChild(card);
      return item;
    }
    nextPath.add(key);

    const label = element('button', 'node-label');
    label.type = 'button';
    label.setAttribute('aria-expanded', 'false');
    const nodeWarnings = dangerText(group).map((warning) => warning.text).join('. ');
    label.setAttribute('aria-label', `${groupName(group)}. Show or hide group details.${nodeWarnings ? ` ${nodeWarnings}` : ''}`);
    const abbreviatedName = logic.abbreviate(groupName(group), options.maxNameLength, options.abbreviationStyle);
    const name = element('span', 'node-name', abbreviatedName);
    name.title = groupName(group);
    label.appendChild(name);
    addWarnings(label, group, true);
    const panelId = `meta-${group.id}-${Math.random().toString(36).slice(2)}`;
    label.setAttribute('aria-controls', panelId);
    const panel = createMetaPanel(group);
    panel.id = panelId;
    panel.hidden = true;
    label.addEventListener('click', () => {
      panel.hidden = !panel.hidden;
      label.setAttribute('aria-expanded', String(!panel.hidden));
    });
    card.appendChild(label);
    card.appendChild(panel);

    const related = getRelations(group, direction);
    if (related.length) {
      const branchId = `branch-${group.id}-${direction}-${Math.random().toString(36).slice(2)}`;
      const branch = document.createElement('ul');
      branch.className = 'branch-list';
      branch.id = branchId;
      // Large branches start collapsed so one wide group does not bury the rest of the diagram.
      branch.hidden = level >= Number(options.initialDepth || 2) ||
        (autoExpandLimit > 0 && related.length > autoExpandLimit);
      let relatedIndex = 0;
      let moreItem = null;
      let allBranchNodesRendered = false;
      const populateBranch = () => {
        if (allBranchNodesRendered || moreItem) return;
        while (relatedIndex < related.length) {
          const childNode = createBranchNode(related[relatedIndex], direction, level + 1, nextPath);
          if (!childNode) {
            moreItem = createMoreButton(branch, direction, related.length - relatedIndex, () => {
              moreItem = null;
              populateBranch();
            });
            return;
          }
          branch.appendChild(childNode);
          relatedIndex += 1;
        }
        allBranchNodesRendered = true;
      };
      if (!branch.hidden) populateBranch();
      const branchToggle = element('button', 'branch-toggle', `${branch.hidden ? 'Expand' : 'Collapse'} ${related.length} related group(s)`);
      branchToggle.type = 'button';
      branchToggle.setAttribute('aria-expanded', String(!branch.hidden));
      branchToggle.setAttribute('aria-controls', branchId);
      branchToggle.addEventListener('click', () => {
        branch.hidden = !branch.hidden;
        if (!branch.hidden) populateBranch();
        branchToggle.setAttribute('aria-expanded', String(!branch.hidden));
        branchToggle.textContent = `${branch.hidden ? 'Expand' : 'Collapse'} ${related.length} related group(s)`;
      });
      card.appendChild(branchToggle);
      card.appendChild(branch);
    }
    item.appendChild(card);
    return item;
  }

  function createTree(group, direction, targetId) {
    const target = document.getElementById(targetId);
    target.replaceChildren();
    renderedNodeCount[direction] = 0;
    nodeBudget[direction] = 400;
    const related = getRelations(group, direction);
    let relationIndex = 0;
    let moreItem = null;
    const populateTree = () => {
      if (moreItem) return;
      while (relationIndex < related.length) {
        const node = createBranchNode(related[relationIndex], direction, 0, new Set([String(group.id).toLowerCase()]));
        if (!node) {
          moreItem = createMoreButton(target, direction, related.length - relationIndex, () => {
            moreItem = null;
            populateTree();
          });
          return;
        }
        target.appendChild(node);
        relationIndex += 1;
      }
    };
    populateTree();
    if (!related.length) {
      const empty = document.createElement('li');
      empty.appendChild(element('p', 'empty-message', 'No related groups'));
      target.appendChild(empty);
    }
  }

  function createCenterCard(group) {
    const card = document.getElementById('centerCard');
    card.replaceChildren();
    searchShell.classList.add('is-selected');
    card.appendChild(searchShell);
    const heading = element('div', 'center-heading');
    const title = element('h2', '', groupName(group));
    title.title = groupName(group);
    heading.appendChild(title);
    addWarnings(heading, group);
    heading.appendChild(element('p', '', `${group.type || 'Group'} | ${group.membership || 'membership unknown'} | ${group.id}`));
    card.appendChild(heading);
    const content = element('div', 'center-content');
    const details = document.createElement('dl');
    for (const [label, value] of [
      ['Group id', group.id],
      ['Type', group.type],
      ['Membership', group.membership],
      ['Created', group.created],
      ['Role-assignable', group.roleAssignable ? 'Yes' : 'No'],
      ['On-premises sync', group.onPremSynced ? 'Yes' : 'No']
    ]) {
      if (value === undefined || value === null || value === '') continue;
      details.appendChild(element('dt', '', label));
      details.appendChild(element('dd', '', value));
    }
    content.appendChild(details);
    const description = String(group.description || '');
    if (description) content.appendChild(element('p', '', description));
    addCountTable(content, group.counts || {});
    for (const warning of dangerText(group)) content.appendChild(element('p', 'warning-line', warning.text));
    if (Array.isArray(group.flags) && group.flags.length) {
      content.appendChild(element('p', 'warning-line', `Data quality: ${group.flags.join(', ')}`));
    }
    card.appendChild(content);
  }

  function selectGroup(group, updateUrl = true) {
    selectedGroup = group;
    search.value = groupName(group);
    suggestions.hidden = true;
    search.setAttribute('aria-expanded', 'false');
    searchShell.classList.add('is-selected');
    selectedView.hidden = false;
    createCenterCard(group);
    createTree(group, 'parents', 'parentsTree');
    createTree(group, 'children', 'childrenTree');
    document.getElementById('snapshotLine').textContent = `Data from ${data.generatedAt || 'unknown snapshot'}`;
    searchStatus.textContent = `Selected ${groupName(group)}`;
    if (updateUrl) {
      const nextUrl = logic.withGroupInHash(location.href, group.id);
      if (nextUrl !== location.href) {
        try {
          history.pushState({ groupId: group.id }, '', nextUrl);
        } catch (error) {
          if (!(error instanceof DOMException) || error.name !== 'SecurityError') throw error;
          try {
            location.hash = new URL(nextUrl).hash;
          } catch (fallbackError) {
            searchStatus.textContent = `Selected ${groupName(group)}, but the link could not be updated: ${fallbackError.message}`;
          }
        }
      }
    }
  }

  function showSearchOnly(message) {
    selectedGroup = null;
    selectedView.hidden = true;
    searchShell.classList.remove('is-selected');
    selectedView.before(searchShell);
    search.value = '';
    suggestions.hidden = true;
    search.setAttribute('aria-expanded', 'false');
    search.setAttribute('aria-activedescendant', '');
    searchStatus.textContent = message;
  }

  function selectGroupFromUrl() {
    const link = logic.parseGroupLink(location.href);
    if (!link.present) {
      if (selectedGroup) showSearchOnly('');
      return;
    }
    if (!link.valid) {
      showSearchOnly('The group link is invalid. Search for a group to select it.');
      return;
    }
    const group = getGroup(link.id);
    if (!group) {
      showSearchOnly(`The linked group is not in this report (snapshot ${data.generatedAt || 'unknown'}).`);
      return;
    }
    if (!selectedGroup || String(selectedGroup.id).toLowerCase() !== link.id) selectGroup(group, false);
  }

  function renderSuggestions() {
    const query = search.value;
    suggestions.replaceChildren();
    activeIndex = -1;
    if (!query.trim()) {
      suggestions.hidden = true;
      search.setAttribute('aria-expanded', 'false');
      search.setAttribute('aria-activedescendant', '');
      searchStatus.textContent = selectedGroup ? `Selected ${groupName(selectedGroup)}` : '';
      return;
    }
    const results = logic.searchGroups(query, groups, 50);
    results.forEach((group, index) => {
      const option = element('button', 'suggestion');
      option.type = 'button';
      option.id = `suggestion-${index}`;
      option.setAttribute('role', 'option');
      option.setAttribute('aria-selected', 'false');
      const optionWarnings = dangerText(group).map((warning) => warning.text).join('. ');
      option.setAttribute('aria-label', [groupName(group), group.type, group.id, optionWarnings].filter(Boolean).join('. '));
      const optionName = element('span', 'suggestion-name', logic.abbreviate(groupName(group), options.maxNameLength, options.abbreviationStyle));
      optionName.title = groupName(group);
      option.appendChild(optionName);
      addWarnings(option, group);
      option.appendChild(element('span', 'suggestion-detail', `${group.type || 'Group'} | ${group.id} | Users ${formatCount(group.counts && group.counts.nested && group.counts.nested.users)}, Devices ${formatCount(group.counts && group.counts.nested && group.counts.nested.devices)}, Groups ${formatCount(group.counts && group.counts.nested && group.counts.nested.groups)}`));
      option.addEventListener('mousedown', (event) => event.preventDefault());
      option.addEventListener('click', () => selectGroup(group));
      suggestions.appendChild(option);
    });
    suggestions.hidden = false;
    search.setAttribute('aria-expanded', 'true');
    searchStatus.textContent = !results.length
      ? 'No group matches the text you typed'
      : results.total > results.length
        ? `Showing ${results.length} of ${results.total} matches. Keep typing to narrow the list.`
        : `${results.length} matching group(s)`;
  }

  function setActiveSuggestion(nextIndex) {
    const optionsList = Array.from(suggestions.querySelectorAll('[role="option"]'));
    if (!optionsList.length) return;
    activeIndex = Math.max(0, Math.min(nextIndex, optionsList.length - 1));
    optionsList.forEach((option, index) => option.setAttribute('aria-selected', String(index === activeIndex)));
    search.setAttribute('aria-activedescendant', optionsList[activeIndex].id);
    optionsList[activeIndex].scrollIntoView({ block: 'nearest' });
  }

  search.addEventListener('input', renderSuggestions);
  search.addEventListener('keydown', (event) => {
    const optionCount = suggestions.querySelectorAll('[role="option"]').length;
    if (event.key === 'ArrowDown' && optionCount) {
      event.preventDefault();
      setActiveSuggestion(activeIndex + 1);
    } else if (event.key === 'ArrowUp' && optionCount) {
      event.preventDefault();
      setActiveSuggestion(activeIndex < 0 ? optionCount - 1 : activeIndex - 1);
    } else if (event.key === 'Enter' && activeIndex >= 0 && optionCount) {
      event.preventDefault();
      const selected = logic.searchGroups(search.value, groups, 50)[activeIndex];
      if (selected) selectGroup(selected);
    } else if (event.key === 'Escape') {
      suggestions.hidden = true;
      search.setAttribute('aria-expanded', 'false');
      search.setAttribute('aria-activedescendant', '');
      if (selectedGroup) search.value = groupName(selectedGroup);
    } else if (event.key === 'Home' && optionCount) {
      event.preventDefault();
      setActiveSuggestion(0);
    } else if (event.key === 'End' && optionCount) {
      event.preventDefault();
      setActiveSuggestion(optionCount - 1);
    }
  });

  document.getElementById('expandAll').addEventListener('click', () => {
    let expandedCount = 0;
    while (expandedCount < 400) {
      const collapsed = Array.from(document.querySelectorAll('.branch-toggle'))
        .find((button) => button.getAttribute('aria-expanded') === 'false');
      if (!collapsed) break;
      collapsed.click();
      expandedCount += 1;
    }
  });
  document.getElementById('collapseAll').addEventListener('click', () => {
    document.querySelectorAll('.branch-list').forEach((list) => { list.hidden = true; });
    document.querySelectorAll('.branch-toggle').forEach((button) => {
      button.setAttribute('aria-expanded', 'false');
      button.textContent = button.textContent.replace(/^Collapse/, 'Expand');
    });
  });
  const diagram = document.getElementById('selectedView');
  function applyZoom() {
    diagram.className = `selected-view zoom-${Math.round(zoom * 100)}`;
  }
  document.getElementById('zoomIn').addEventListener('click', () => { zoom = Math.min(1.5, zoom + 0.1); applyZoom(); });
  document.getElementById('zoomOut').addEventListener('click', () => { zoom = Math.max(0.6, zoom - 0.1); applyZoom(); });
  document.getElementById('zoomReset').addEventListener('click', () => { zoom = 1; applyZoom(); });

  window.addEventListener('popstate', selectGroupFromUrl);
  window.addEventListener('hashchange', selectGroupFromUrl);
  selectGroupFromUrl();
}());
