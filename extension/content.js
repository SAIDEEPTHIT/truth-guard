// TruthShield Content Script
// Captures selected text and sends it to the background script for analysis

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "get_selection") {
    const selectedText = window.getSelection().toString().trim();
    sendResponse({ text: selectedText });
  }
});
