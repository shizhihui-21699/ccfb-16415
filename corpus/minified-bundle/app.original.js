// Merely illustrative original; the shipped file is minified below.
function handleWidgetMessage(event) {
  if (event.origin.indexOf('https://widget.bundle-corp.test') !== 0) return;
  document.getElementById('slot').innerHTML = event.data.html;
}
window.addEventListener('message', handleWidgetMessage);
