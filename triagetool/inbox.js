const repo = document.querySelector('#repo');
const search = document.querySelector('#search');
const cards = [...document.querySelectorAll('article')];
const levelButtons = [...document.querySelectorAll('[data-set-level]')];
const contents = document.querySelector('#contents');
const levels = levelButtons.map(button => button.dataset.setLevel);
let selected = null;

// every word typed has to be found in a card, letter after letter but not necessarily side by side
function found(text, word) {
  let position = 0;
  for (const letter of word) {
    position = text.indexOf(letter, position) + 1;
    if (position === 0) return false;
  }
  return true;
}

function filter() {
  const words = search.value.toLowerCase().split(' ').filter(word => word !== '');
  for (const card of cards) {
    const wrongRepo = repo.value !== '' && card.dataset.repo !== repo.value;
    const everyWordFound = words.every(word => found(card.dataset.search, word));
    card.hidden = wrongRepo || !everyWordFound;
    contentsLink(card).hidden = card.hidden;
  }
  for (const part of contents.querySelectorAll('.part')) {
    part.hidden = part.querySelector('a:not([hidden])') === null;
  }
  for (const section of document.querySelectorAll('section')) {
    section.hidden = section.querySelector('article:not([hidden])') === null;
  }
}

function contentsLink(card) {
  return contents.querySelector(`a[href="#${card.id}"]`);
}

function setLevel(level) {
  localStorage.setItem('level', level);
  for (const card of cards) card.dataset.level = level;
  for (const button of levelButtons) button.disabled = button.dataset.setLevel === level;
}

// the level one step further out (-1) or in (+1), staying within short and full
function zoomedFrom(level, step) {
  const index = levels.indexOf(level) + step;
  return levels[Math.max(0, Math.min(levels.length - 1, index))];
}

// zooms one card in, and back out to short once it is at full
function zoomCard(card) {
  const atFull = card.dataset.level === levels[levels.length - 1];
  card.dataset.level = atFull ? levels[0] : zoomedFrom(card.dataset.level, 1);
}

function select(card) {
  if (selected !== null) {
    selected.classList.remove('selected');
    contentsLink(selected).classList.remove('current');
  }
  selected = card;
  selected.classList.add('selected');
  selected.scrollIntoView({block: 'nearest'});
  contentsLink(selected).classList.add('current');
  contentsLink(selected).scrollIntoView({block: 'nearest'});
  // the address remembers the report, so a reload or a shared link comes back to it
  history.replaceState(null, '', '#' + selected.id);
}

function move(step) {
  const visible = cards.filter(card => !card.hidden);
  if (visible.length === 0) return;
  let index = visible.indexOf(selected) + step;
  index = Math.max(0, Math.min(visible.length - 1, index));
  select(visible[index]);
}

function onKey(event) {
  const typing = ['INPUT', 'SELECT'].includes(event.target.tagName);
  if (typing) {
    if (event.key === 'Escape') event.target.blur();
    return;
  }
  if (event.metaKey || event.ctrlKey || event.altKey) return;
  if (event.key === 'j') move(1);
  if (event.key === 'k') move(-1);
  if (event.key === 'o' && selected !== null) window.open(selected.dataset.url, '_blank');
  if (event.key === 'Enter' && selected !== null) zoomCard(selected);
  if (event.key === '-') setLevel(zoomedFrom(localStorage.getItem('level'), -1));
  if (event.key === '+' || event.key === '=') setLevel(zoomedFrom(localStorage.getItem('level'), 1));
  if (event.key === '?') toggleHelp();
  if (event.key === '/') {
    event.preventDefault();
    search.focus();
  }
}

function onCardClick(event) {
  const onControl = event.target.closest('a, button, input, form') !== null;
  const selectingText = window.getSelection().toString() !== '';
  if (onControl || selectingText) return;
  select(event.currentTarget);
}

function toggleHelp() {
  const keys = document.querySelector('#keys');
  keys.hidden = !keys.hidden;
}

document.querySelector('#help').onclick = toggleHelp;
// on a narrow window the list on the left is closed until asked for, and closes again once a report is picked
document.querySelector('#show-contents').onclick = () => contents.classList.toggle('open');
contents.onclick = () => contents.classList.remove('open');
// a button that reloads the page keeps the address pointing at the selected report
for (const form of document.querySelectorAll('form')) {
  form.onsubmit = () => { form.action = form.getAttribute('action') + location.hash; };
}
document.querySelector('#reload').onclick = event => {
  event.preventDefault();
  location.reload();
};
repo.onchange = filter;
search.oninput = filter;
document.onkeydown = onKey;
for (const card of cards) card.onclick = onCardClick;
for (const button of levelButtons) button.onclick = () => setLevel(button.dataset.setLevel);
setLevel(levels.includes(localStorage.getItem('level')) ? localStorage.getItem('level') : 'medium');
// the address names a report: on opening the page, and each time a link in the list on the left is followed
function selectFromAddress() {
  const linked = document.getElementById(location.hash.slice(1));
  if (linked !== null && linked.tagName === 'ARTICLE') select(linked);
}
window.onhashchange = selectFromAddress;
selectFromAddress();

// a report is new when it was not on the page, or not in this group, the last time the page was opened
const seen = JSON.parse(localStorage.getItem('seen') || '[]');
const fresh = cards.filter(card => !seen.includes(card.dataset.seen));
for (const card of fresh) card.classList.add('fresh');
if (fresh.length > 0) document.title = `(${fresh.length} new) Triage inbox`;
localStorage.setItem('seen', JSON.stringify(cards.map(card => card.dataset.seen)));

// the server analyses new reports by itself, so the open page asks now and then whether anything moved
async function lookForNews() {
  const response = await fetch('/state');
  const state = await response.text();
  if (state !== document.body.dataset.state) {
    document.title = '(new results) Triage inbox';
    document.querySelector('#reload').hidden = false;
  }
}
setInterval(lookForNews, 60000);
