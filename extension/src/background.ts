// Service worker: the toolbar button opens the side panel in the current window.
// No network, no storage, no messaging here; the page does everything.

chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => { /* older Chrome */ });
});

chrome.action.onClicked.addListener((tab) => {
  if (tab.windowId !== undefined) chrome.sidePanel.open({ windowId: tab.windowId }).catch(() => {
    chrome.tabs.create({ url: chrome.runtime.getURL("index.html") });
  });
});
